"""Self-contained bootstrap initializer for the VForge Control Plane.

Automatically configures on stack startup:
1. PostgreSQL role separation (`vforge_migrator`, `vforge_app`) & schema ownership
2. RabbitMQ `vforge` vhost and `vforge_app` user permissions
3. Alembic schema migrations (`alembic upgrade head`)
4. Initial organization (`VForge Security Workspace`), OIDC owner membership, and default runner identity
5. Deterministic ECDSA P-256 mTLS certificates for `runner-gateway` (:8443)
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import ipaddress
import os
import shutil
import subprocess
import time
import urllib.parse
import uuid
from pathlib import Path

import httpx
import psycopg
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

_SECP256R1_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
)
DEFAULT_ORG_ID = "740bca1c-aa68-4b32-a80b-196bc3264390"
DEFAULT_POOL_ID = "c0000001-0000-4000-8000-000000000001"
DEFAULT_RUNNER_ID = "11111111-2222-3333-4444-555555555555"
KEYCLOAK_OWNER_ID = "a8746d5f-41ee-439c-9e81-4ac12b19faf2"


def _derive_ec_key(seed: str, label: str) -> ec.EllipticCurvePrivateKey:
    digest = hmac.new(seed.encode("utf-8"), label.encode("utf-8"), hashlib.sha256).digest()
    scalar = (int.from_bytes(digest, "big") % (_SECP256R1_ORDER - 1)) + 1
    return ec.derive_private_key(scalar, ec.SECP256R1())


def generate_mtls_certs(cert_dir: Path, seed: str, vm1_ip: str) -> None:
    cert_dir.mkdir(parents=True, exist_ok=True)
    ca_key = _derive_ec_key(seed, "vforge-runner-ca-v1")
    gw_key = _derive_ec_key(seed, "vforge-runner-gateway-v1")

    not_before = datetime.datetime(2026, 1, 1, 0, 0, 0, tzinfo=datetime.UTC)
    not_after = datetime.datetime(2031, 1, 1, 0, 0, 0, tzinfo=datetime.UTC)

    ca_name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VForge"),
            x509.NameAttribute(NameOID.COMMON_NAME, "VForge Runner Root CA"),
        ]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(1001)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    san_entries: list[x509.GeneralName] = [
        x509.DNSName("runner-gateway"),
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
    ]
    try:
        san_entries.append(x509.IPAddress(ipaddress.ip_address(vm1_ip)))
    except ValueError:
        san_entries.append(x509.DNSName(vm1_ip))

    gw_name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VForge"),
            x509.NameAttribute(NameOID.COMMON_NAME, "runner-gateway"),
        ]
    )
    gw_cert = (
        x509.CertificateBuilder()
        .subject_name(gw_name)
        .issuer_name(ca_name)
        .public_key(gw_key.public_key())
        .serial_number(1002)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    (cert_dir / "ca.crt").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    (cert_dir / "gateway.crt").write_bytes(gw_cert.public_bytes(serialization.Encoding.PEM))
    (cert_dir / "gateway.key").write_bytes(
        gw_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    for fname in ("ca.crt", "gateway.crt", "gateway.key"):
        os.chmod(cert_dir / fname, 0o644)
    print(f"[init] Generated Runner Gateway mTLS certificates in {cert_dir}")


def setup_postgres_roles() -> None:
    pg_host = os.environ.get("POSTGRES_HOST", "postgres")
    pg_port = int(os.environ.get("POSTGRES_PORT", "5432"))
    pg_db = os.environ.get("POSTGRES_DB", "vforge")
    pg_super_pw = os.environ["POSTGRES_PASSWORD"]
    pg_mig_pw = os.environ["POSTGRES_MIGRATOR_PASSWORD"]
    pg_app_pw = os.environ["POSTGRES_APP_PASSWORD"]

    conninfo = f"host={pg_host} port={pg_port} dbname={pg_db} user=vforge password={pg_super_pw}"
    with psycopg.connect(conninfo, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute(
            """
            DO $$
            BEGIN
              IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vforge_migrator') THEN
                CREATE ROLE vforge_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
                  NOINHERIT NOREPLICATION NOBYPASSRLS;
              END IF;
              IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vforge_app') THEN
                CREATE ROLE vforge_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
                  NOINHERIT NOREPLICATION NOBYPASSRLS;
              END IF;
            END
            $$;
            """
        )
        cur.execute(
            psycopg.sql.SQL("ALTER ROLE vforge_migrator WITH PASSWORD {}").format(
                psycopg.sql.Literal(pg_mig_pw)
            )
        )
        cur.execute(
            psycopg.sql.SQL("ALTER ROLE vforge_app WITH PASSWORD {}").format(
                psycopg.sql.Literal(pg_app_pw)
            )
        )
        cur.execute("ALTER DATABASE vforge OWNER TO vforge_migrator;")
        cur.execute("ALTER SCHEMA public OWNER TO vforge_migrator;")
        cur.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC;")
        cur.execute("GRANT USAGE ON SCHEMA public TO vforge_app;")
        cur.execute("REVOKE ALL ON DATABASE vforge FROM PUBLIC;")
        cur.execute("GRANT CONNECT ON DATABASE vforge TO vforge_migrator, vforge_app;")
    print("[init] PostgreSQL least-privilege roles (vforge_migrator, vforge_app) configured.")


def setup_rabbitmq() -> None:
    rmq_host = os.environ.get("RABBITMQ_HOST", "rabbitmq")
    rmq_admin_user = os.environ.get("RABBITMQ_ADMIN_USER", "vforge_admin")
    rmq_admin_pw = os.environ["RABBITMQ_ADMIN_PASSWORD"]
    rmq_app_user = os.environ.get("RABBITMQ_APP_USER", "vforge_app")
    rmq_app_pw = os.environ["RABBITMQ_APP_PASSWORD"]
    vhost = os.environ.get("RABBITMQ_VHOST", "vforge")
    encoded_vhost = urllib.parse.quote(vhost, safe="")

    base_url = f"http://{rmq_host}:15672/api"
    auth = (rmq_admin_user, rmq_admin_pw)

    with httpx.Client(base_url=base_url, auth=auth, timeout=10.0) as client:
        for _ in range(30):
            try:
                r = client.get("/overview")
                if r.status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(2)

        client.put(f"/vhosts/{encoded_vhost}", json={"description": "VForge Control Plane"})
        client.put(
            f"/users/{urllib.parse.quote(rmq_app_user, safe='')}",
            json={"password": rmq_app_pw, "tags": ""},
        )
        perm_body = {"configure": ".*", "write": ".*", "read": ".*"}
        client.put(
            f"/permissions/{encoded_vhost}/{urllib.parse.quote(rmq_app_user, safe='')}",
            json=perm_body,
        )
        client.put(
            f"/permissions/{encoded_vhost}/{urllib.parse.quote(rmq_admin_user, safe='')}",
            json=perm_body,
        )
    print("[init] RabbitMQ vhost and vforge_app user permissions configured.")


def run_alembic_migrations() -> None:
    subprocess.run(["alembic", "upgrade", "head"], check=True)
    print("[init] Alembic migrations upgraded to head.")


def _derive_default_runner_cert_metadata(seed: str) -> tuple[str, str, str, datetime.datetime]:
    ca_key = _derive_ec_key(seed, "vforge-runner-ca-v1")
    runner_key = _derive_ec_key(seed, f"vforge-runner-client-{DEFAULT_RUNNER_ID}-v1")
    not_before = datetime.datetime(2026, 1, 1, 0, 0, 0, tzinfo=datetime.UTC)
    not_after = datetime.datetime(2031, 1, 1, 0, 0, 0, tzinfo=datetime.UTC)
    ca_name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VForge"),
            x509.NameAttribute(NameOID.COMMON_NAME, "VForge Runner Root CA"),
        ]
    )
    spiffe_uri = f"spiffe://vforge/org/{DEFAULT_ORG_ID}/runner/{DEFAULT_RUNNER_ID}"
    runner_name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VForge"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"vforge-runner-{DEFAULT_RUNNER_ID}"),
        ]
    )
    runner_cert = (
        x509.CertificateBuilder()
        .subject_name(runner_name)
        .issuer_name(ca_name)
        .public_key(runner_key.public_key())
        .serial_number(2001)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_uri)]),
            critical=False,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )
    cert_sha256 = hashlib.sha256(
        runner_cert.public_bytes(serialization.Encoding.DER)
    ).hexdigest()
    cert_subject = runner_cert.subject.rfc4514_string()
    return spiffe_uri, cert_sha256, cert_subject, not_after


def seed_default_workspace(vm1_ip: str, seed: str) -> None:
    pg_host = os.environ.get("POSTGRES_HOST", "postgres")
    pg_port = int(os.environ.get("POSTGRES_PORT", "5432"))
    pg_db = os.environ.get("POSTGRES_DB", "vforge")
    pg_super_pw = os.environ["POSTGRES_PASSWORD"]
    oidc_issuer = os.environ.get("OIDC_ISSUER", f"http://{vm1_ip}:8080/realms/vforge")
    spiffe_uri, cert_sha256, cert_subject, cert_expires_at = _derive_default_runner_cert_metadata(
        seed
    )

    conninfo = f"host={pg_host} port={pg_port} dbname={pg_db} user=vforge password={pg_super_pw}"
    with psycopg.connect(conninfo, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO organizations (id, name, slug, status)
            VALUES (%s, 'VForge Security Workspace', 'vforge-security', 'active')
            ON CONFLICT (id) DO NOTHING;
            """,
            (DEFAULT_ORG_ID,),
        )
        cur.execute(
            """
            INSERT INTO app_users (id, oidc_issuer, oidc_subject, email, display_name)
            VALUES (%s, %s, %s, 'dev-owner@vforge.local', 'Dev Owner')
            ON CONFLICT (oidc_issuer, oidc_subject)
            DO UPDATE SET email = EXCLUDED.email
            RETURNING id;
            """,
            (KEYCLOAK_OWNER_ID, oidc_issuer, KEYCLOAK_OWNER_ID),
        )
        row = cur.fetchone()
        user_id = row[0] if row else uuid.UUID(KEYCLOAK_OWNER_ID)
        cur.execute(
            """
            INSERT INTO memberships (id, organization_id, user_id, role)
            VALUES ('b0000001-0000-4000-8000-000000000001', %s, %s, 'owner')
            ON CONFLICT (organization_id, user_id) DO NOTHING;
            """,
            (DEFAULT_ORG_ID, user_id),
        )
        cur.execute(
            """
            INSERT INTO runner_pools (id, organization_id, name, slug, pool_type, max_concurrent_jobs, active)
            VALUES (%s, %s, 'Default Execution Pool', 'default-pool', 'standard', 4, true)
            ON CONFLICT (organization_id, slug) DO NOTHING
            RETURNING id;
            """,
            (DEFAULT_POOL_ID, DEFAULT_ORG_ID),
        )
        pool_row = cur.fetchone()
        pool_id = pool_row[0] if pool_row else uuid.UUID(DEFAULT_POOL_ID)
        cur.execute(
            """
            INSERT INTO runners (
                id, organization_id, pool_id, name, runner_identity,
                cert_sha256, cert_subject, cert_expires_at, status, version, capabilities_json
            )
            VALUES (
                %s, %s, %s, 'vforge-runner-1', %s,
                %s, %s, %s, 'active', '0.1.0',
                '{"adapters": ["opengrep", "gitleaks", "syft", "grype", "checkov", "zap", "nuclei", "nmap", "testssl"]}'::jsonb
            )
            ON CONFLICT (id) DO UPDATE SET
                cert_sha256 = EXCLUDED.cert_sha256,
                cert_subject = EXCLUDED.cert_subject,
                cert_expires_at = EXCLUDED.cert_expires_at,
                status = 'active';
            """,
            (
                DEFAULT_RUNNER_ID,
                DEFAULT_ORG_ID,
                pool_id,
                spiffe_uri,
                cert_sha256,
                cert_subject,
                cert_expires_at,
            ),
        )
    print(f"[init] Seeded workspace {DEFAULT_ORG_ID} and default runner {DEFAULT_RUNNER_ID}.")


def populate_static_volumes() -> None:
    opa_dst = Path("/run/opa-policies")
    kc_dst = Path("/run/keycloak-import")
    opa_src = Path("/opt/policies/rego")
    kc_src = Path("/opt/infrastructure/keycloak")

    if opa_src.exists():
        opa_dst.mkdir(parents=True, exist_ok=True)
        shutil.copytree(opa_src, opa_dst, dirs_exist_ok=True)
        for p in opa_dst.rglob("*"):
            os.chmod(p, 0o755 if p.is_dir() else 0o644)
        os.chmod(opa_dst, 0o755)

    if kc_src.exists():
        kc_dst.mkdir(parents=True, exist_ok=True)
        shutil.copytree(kc_src, kc_dst, dirs_exist_ok=True)
        for p in kc_dst.rglob("*"):
            os.chmod(p, 0o755 if p.is_dir() else 0o644)
        os.chmod(kc_dst, 0o755)
    print("[init] Populated OPA policy and Keycloak realm volumes.")


def main() -> None:
    vm1_ip = os.environ.get("VM1_IP", "192.168.1.110")
    seed = os.environ.get("RUNNER_MTLS_SEED_SECRET", "vforge-proxmox-mtls-seed-v1")
    cert_dir = Path(os.environ.get("RUNNER_GATEWAY_CERT_DIR", "/run/runner-gateway"))

    populate_static_volumes()
    generate_mtls_certs(cert_dir, seed, vm1_ip)
    setup_postgres_roles()
    setup_rabbitmq()
    run_alembic_migrations()
    seed_default_workspace(vm1_ip, seed)
    print("[init] Control Plane initialization complete.")


if __name__ == "__main__":
    main()

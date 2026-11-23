"""Self-contained Portainer GitOps mTLS certificate bootstrap for VForge Runner (VM-2).

Derives the matching Runner Root CA and ECDSA P-256 client certificate (`spiffe://vforge/...`)
from `RUNNER_MTLS_SEED_SECRET` so VM-2 can be deployed directly from Portainer UI without manual scp.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

_SECP256R1_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
)
DEFAULT_ORG_ID = "740bca1c-aa68-4b32-a80b-196bc3264390"
DEFAULT_RUNNER_ID = "11111111-2222-3333-4444-555555555555"


def _derive_ec_key(seed: str, label: str) -> ec.EllipticCurvePrivateKey:
    digest = hmac.new(seed.encode("utf-8"), label.encode("utf-8"), hashlib.sha256).digest()
    scalar = (int.from_bytes(digest, "big") % (_SECP256R1_ORDER - 1)) + 1
    return ec.derive_private_key(scalar, ec.SECP256R1())


def main() -> None:
    seed = os.environ.get("RUNNER_MTLS_SEED_SECRET", "vforge-proxmox-mtls-seed-v1")
    org_id = os.environ.get("RUNNER_ORGANIZATION_ID", DEFAULT_ORG_ID)
    runner_id = os.environ.get("RUNNER_ID", DEFAULT_RUNNER_ID)
    cert_dir = Path(os.environ.get("RUNNER_CERT_DIR", "/run/runner-certs"))
    cert_dir.mkdir(parents=True, exist_ok=True)

    ca_key = _derive_ec_key(seed, "vforge-runner-ca-v1")
    runner_key = _derive_ec_key(seed, f"vforge-runner-client-{runner_id}-v1")

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

    spiffe_uri = f"spiffe://vforge/org/{org_id}/runner/{runner_id}"
    runner_name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VForge"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"vforge-runner-{runner_id}"),
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

    (cert_dir / "ca.crt").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    (cert_dir / "runner.crt").write_bytes(runner_cert.public_bytes(serialization.Encoding.PEM))
    (cert_dir / "runner.key").write_bytes(
        runner_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    for fname in ("ca.crt", "runner.crt", "runner.key"):
        os.chmod(cert_dir / fname, 0o644)
    print(f"[runner-cert-init] Generated mTLS certs for {spiffe_uri} in {cert_dir}")


if __name__ == "__main__":
    main()

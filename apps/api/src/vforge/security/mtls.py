"""Mutual-TLS X.509 runner identity parsing, verification, and PKI test/dev helpers."""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

_SPIFFE_RUNNER_RE = re.compile(
    r"^spiffe://vforge/org/([0-9a-fA-F-]{36})/runner/([0-9a-fA-F-]{36})$"
)


@dataclass(frozen=True, slots=True)
class RunnerCertClaims:
    """Cryptographically extracted identity claims from an mTLS client certificate."""

    organization_id: uuid.UUID
    runner_id: uuid.UUID
    runner_identity: str
    cert_sha256: str
    cert_subject: str
    expires_at: datetime


def extract_cert_sha256_and_subject(cert_pem: str) -> tuple[str, str, datetime, str]:
    """Validate public X.509 runner certificate PEM and extract registration claims."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    der_bytes = cert.public_bytes(serialization.Encoding.DER)
    claims = verify_runner_cert_der(der_bytes)
    return (
        claims.cert_sha256,
        claims.cert_subject,
        claims.expires_at,
        claims.runner_identity,
    )


def parse_runner_spiffe_identity(cert: x509.Certificate) -> tuple[uuid.UUID, uuid.UUID, str]:
    """Extract and validate SPIFFE runner SAN URI (`spiffe://vforge/org/<id>/runner/<id>`)."""
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound as exc:
        raise ValueError(
            "Runner certificate must include SubjectAlternativeName extension"
        ) from exc

    uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    matched: list[tuple[uuid.UUID, uuid.UUID, str]] = []
    for uri in uris:
        m = _SPIFFE_RUNNER_RE.match(uri.strip())
        if m:
            matched.append((uuid.UUID(m.group(1)), uuid.UUID(m.group(2)), uri.strip()))

    if len(matched) != 1:
        raise ValueError(
            "Runner certificate must specify exactly one SPIFFE SAN URI "
            "matching spiffe://vforge/org/<org_id>/runner/<runner_id>"
        )
    return matched[0]


def verify_runner_cert_der(
    cert_der: bytes,
    *,
    now: datetime | None = None,
) -> RunnerCertClaims:
    """Parse X.509 DER certificate presented at TLS handshake and validate runner constraints."""
    cert = x509.load_der_x509_certificate(cert_der)
    current = now or datetime.now(UTC)

    if current < cert.not_valid_before_utc or current >= cert.not_valid_after_utc:
        raise ValueError("Runner client certificate is expired or not yet valid")

    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if ExtendedKeyUsageOID.CLIENT_AUTH not in eku:
            raise ValueError("Runner certificate ExtendedKeyUsage lacks CLIENT_AUTH")
    except x509.ExtensionNotFound as exc:
        raise ValueError("Runner certificate must include ExtendedKeyUsage=CLIENT_AUTH") from exc

    org_id, runner_id, identity_uri = parse_runner_spiffe_identity(cert)
    cert_sha256 = hashlib.sha256(cert_der).hexdigest()
    subject_str = cert.subject.rfc4514_string()
    return RunnerCertClaims(
        organization_id=org_id,
        runner_id=runner_id,
        runner_identity=identity_uri,
        cert_sha256=cert_sha256,
        cert_subject=subject_str,
        expires_at=cert.not_valid_after_utc,
    )


def _issuer_aki_extension(ca_cert: x509.Certificate) -> x509.AuthorityKeyIdentifier:
    try:
        ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)
    except x509.ExtensionNotFound:
        ca_pub = ca_cert.public_key()
        assert isinstance(ca_pub, ec.EllipticCurvePublicKey)
        return x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_pub)


def generate_runner_ca(
    *,
    common_name: str = "VForge Runner CA",
    valid_days: int = 365,
) -> tuple[str, str]:
    """Generate an ECDSA P-256 X.509 CA certificate + private key PEM pair."""
    ca_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    ca_pub = ca_key.public_key()
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
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
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_pub), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_pub), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return (
        ca_cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii"),
    )


def issue_signed_runner_cert(
    *,
    ca_cert_pem: str,
    ca_key_pem: str,
    organization_id: uuid.UUID,
    runner_id: uuid.UUID,
    common_name: str | None = None,
    valid_days: int = 90,
) -> tuple[str, str, RunnerCertClaims]:
    """Issue a CA-signed mTLS client certificate bound to a single tenant and runner UUID."""
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode("utf-8"))
    ca_key = serialization.load_pem_private_key(ca_key_pem.encode("utf-8"), password=None)
    assert isinstance(ca_key, ec.EllipticCurvePrivateKey)

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_pub = leaf_key.public_key()
    spiffe_uri = f"spiffe://vforge/org/{organization_id}/runner/{runner_id}"
    cn = common_name or f"runner-{runner_id}"
    now = datetime.now(UTC)

    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=valid_days))
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
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_pub), critical=False)
        .add_extension(_issuer_aki_extension(ca_cert), critical=False)
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_uri)]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    cert_pem = leaf_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    key_pem = leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    claims = verify_runner_cert_der(leaf_cert.public_bytes(serialization.Encoding.DER))
    return cert_pem, key_pem, claims


def issue_signed_gateway_cert(
    *,
    ca_cert_pem: str,
    ca_key_pem: str,
    dns_names: list[str] | None = None,
    ip_addresses: list[str] | None = None,
    common_name: str = "runner-gateway",
    valid_days: int = 90,
) -> tuple[str, str]:
    """Issue a CA-signed TLS server certificate for the dedicated runner mTLS gateway."""
    import ipaddress

    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode("utf-8"))
    ca_key = serialization.load_pem_private_key(ca_key_pem.encode("utf-8"), password=None)
    assert isinstance(ca_key, ec.EllipticCurvePrivateKey)

    srv_key = ec.generate_private_key(ec.SECP256R1())
    srv_pub = srv_key.public_key()
    now = datetime.now(UTC)
    san_entries: list[x509.GeneralName] = [
        x509.DNSName(name) for name in (dns_names or ["runner-gateway", "localhost"])
    ]
    for ip_str in ip_addresses or ["127.0.0.1"]:
        san_entries.append(x509.IPAddress(ipaddress.ip_address(ip_str)))

    srv_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(srv_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=valid_days))
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
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(srv_pub), critical=False)
        .add_extension(_issuer_aki_extension(ca_cert), critical=False)
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return (
        srv_cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        srv_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii"),
    )


def inspect_pem_cert_expiry(
    cert_path: str | Path,
    *,
    label: str,
    warning_days: int = 30,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Inspect an X.509 PEM certificate on disk without exposing any private key material."""
    raw_path = str(cert_path).strip()
    if not raw_path:
        return {
            "label": label,
            "configured": False,
            "status": "not_configured",
            "days_remaining": None,
            "expires_at": None,
            "sha256": None,
            "subject": None,
        }
    p = Path(raw_path)
    if not p.is_file():
        return {
            "label": label,
            "configured": True,
            "status": "missing_file",
            "days_remaining": None,
            "expires_at": None,
            "sha256": None,
            "subject": None,
        }
    try:
        cert = x509.load_pem_x509_certificate(p.read_bytes())
    except ValueError:
        return {
            "label": label,
            "configured": True,
            "status": "malformed_pem",
            "days_remaining": None,
            "expires_at": None,
            "sha256": None,
            "subject": None,
        }
    current = now or datetime.now(UTC)
    remaining_seconds = (cert.not_valid_after_utc - current).total_seconds()
    days_remaining = int(remaining_seconds // 86400)
    if current < cert.not_valid_before_utc:
        cert_status = "not_yet_valid"
    elif current >= cert.not_valid_after_utc:
        cert_status = "expired"
    elif days_remaining <= warning_days:
        cert_status = "expiring_soon"
    else:
        cert_status = "healthy"
    return {
        "label": label,
        "configured": True,
        "status": cert_status,
        "days_remaining": days_remaining,
        "expires_at": cert.not_valid_after_utc.isoformat(),
        "sha256": hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest(),
        "subject": cert.subject.rfc4514_string(),
    }


def inspect_runner_certificate_health(
    *,
    runner_id: str,
    runner_name: str,
    runner_status: str,
    cert_sha256: str,
    cert_expires_at: datetime,
    warning_days: int = 30,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Evaluate a registered runner's mTLS certificate expiry & revocation posture."""
    current = now or datetime.now(UTC)
    expiry = cert_expires_at if cert_expires_at.tzinfo else cert_expires_at.replace(tzinfo=UTC)
    days_remaining = int((expiry - current).total_seconds() // 86400)
    if runner_status == "revoked":
        health = "revoked"
    elif current >= expiry:
        health = "expired"
    elif days_remaining <= warning_days:
        health = "expiring_soon"
    else:
        health = "healthy"
    return {
        "runner_id": runner_id,
        "runner_name": runner_name,
        "runner_status": runner_status,
        "cert_sha256": cert_sha256,
        "cert_expires_at": expiry.isoformat(),
        "days_remaining": days_remaining,
        "cert_health": health,
    }

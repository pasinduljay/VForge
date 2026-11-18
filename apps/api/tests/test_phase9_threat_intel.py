"""Unit and integration tests for Phase 9 Threat Intelligence feeds and enrichment."""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import jwt
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import ASGITransport, AsyncClient
from jwt import PyJWK
from jwt.algorithms import RSAAlgorithm
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.auth.oidc import OidcDiscoveryMetadata, oidc_client
from vforge.config import Settings, get_settings
from vforge.db import build_engine, build_session_factory, set_db_context
from vforge.intel.connector import FeedBatch
from vforge.intel.connectors.cisa_kev import CisaKevConnector
from vforge.intel.connectors.exploit_db import ExploitDbConnector
from vforge.intel.connectors.first_epss import FirstEpssConnector
from vforge.intel.connectors.gated import ShodanGatedConnector, VirusTotalGatedConnector
from vforge.intel.connectors.nvd_cve import NvdCveConnector
from vforge.intel.enrichment import (
    batch_enrich_org_findings,
    enrich_finding_with_intel,
    get_org_threat_intel_summary,
)
from vforge.intel.sync import sync_intelligence_source
from vforge.main import app
from vforge.models.domain import AppUser, Membership, Organization, Project
from vforge.models.enums import Role
from vforge.models.intel import (
    IntelEnrichmentEvent,
    IntelligenceSource,
    IntelRecord,
    IntelRelationship,
    IntelSnapshot,
)
from vforge.models.scanner import Finding
from vforge.security.rate_limit import rate_limiter


def _make_rsa_key(kid: str = "ph9-oidc-key-1") -> tuple[Any, dict[str, Any]]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_jwk = json.loads(RSAAlgorithm.to_jwk(priv.public_key()))
    pub_jwk["kid"] = kid
    pub_jwk["use"] = "sig"
    pub_jwk["alg"] = "RS256"
    return priv, pub_jwk


def _sign_oidc_token(
    priv: Any,
    *,
    issuer: str,
    audience: str,
    subject: str,
    email: str,
    name: str,
    nonce: str,
    kid: str = "ph9-oidc-key-1",
) -> str:
    now = datetime.now(UTC)
    claims = {
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "email": email,
        "name": name,
        "email_verified": True,
        "nonce": nonce,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()) - 1,
        "exp": int((now + timedelta(minutes=15)).timestamp()),
    }
    return jwt.encode(claims, priv, algorithm="RS256", headers={"kid": kid})


def _build_auth_headers(
    ph9_env: dict[str, Any],
    subject: str,
    email: str,
) -> dict[str, str]:
    token = _sign_oidc_token(
        ph9_env["priv"],
        issuer=ph9_env["issuer"],
        audience=ph9_env["client_id"],
        subject=subject,
        email=email,
        name=subject,
        nonce="test-nonce",
    )
    return {
        "Authorization": f"Bearer {token}",
        "X-Correlation-ID": uuid.uuid4().hex,
    }


@pytest_asyncio.fixture
async def ph9_env(tmp_path: Path) -> AsyncIterator[dict[str, Any]]:
    base_settings = get_settings()
    if not base_settings.effective_database_url:
        pytest.skip("Runtime database credentials not configured")

    issuer = "https://idp.ph9.test/realms/vforge"
    client_id = "vforge-api"
    priv, pub_jwk = _make_rsa_key("ph9-oidc-key-1")
    now_mono = time.monotonic()
    jwk_obj = PyJWK.from_dict(pub_jwk)
    oidc_client.reset_caches()
    oidc_client._metadata = OidcDiscoveryMetadata(  # noqa: SLF001
        issuer=issuer,
        authorization_endpoint=f"{issuer}/protocol/openid-connect/auth",
        token_endpoint=f"{issuer}/protocol/openid-connect/token",
        jwks_uri=f"{issuer}/protocol/openid-connect/certs",
    )
    oidc_client._metadata_fetched_at = now_mono  # noqa: SLF001
    oidc_client._jwks_keys = {pub_jwk["kid"]: jwk_obj}  # noqa: SLF001
    oidc_client._jwks_list = [jwk_obj]  # noqa: SLF001
    oidc_client._jwks_fetched_at = now_mono  # noqa: SLF001

    rate_limiter.reset()

    test_settings = Settings(
        vforge_env="test",
        database_url=base_settings.effective_database_url,
        rabbitmq_url=base_settings.effective_rabbitmq_url,
        cache_url="",
        opa_url=base_settings.opa_url,
        oidc_enabled=True,
        oidc_issuer=issuer,
        oidc_client_id=client_id,
        auth_rate_limit_per_minute=10000,
        sensitive_rate_limit_per_minute=10000,
    )

    engine = build_engine(test_settings.effective_database_url)
    session_factory = build_session_factory(engine)
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.dependency_overrides[get_settings] = lambda: test_settings

    yield {
        "settings": test_settings,
        "engine": engine,
        "session_factory": session_factory,
        "priv": priv,
        "issuer": issuer,
        "client_id": client_id,
    }

    app.dependency_overrides.clear()
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(ph9_env: dict[str, Any]) -> AsyncIterator[AsyncSession]:
    factory = ph9_env["session_factory"]
    async with factory() as session:
        async with session.begin():
            yield session


@pytest_asyncio.fixture
async def phase9_fixtures(db_session: AsyncSession, ph9_env: dict[str, Any]) -> dict[str, Any]:
    user_id = uuid.uuid4()
    org_id = uuid.uuid4()
    sub = f"ph9-lead-{uuid.uuid4().hex[:8]}"
    email = f"lead-{uuid.uuid4().hex[:6]}@example.com"

    await set_db_context(db_session, auth_lookup=(ph9_env["issuer"], sub))
    user = AppUser(
        id=user_id,
        oidc_issuer=ph9_env["issuer"],
        oidc_subject=sub,
        email=email,
        display_name="Threat Intel Lead",
        status="active",
    )
    db_session.add(user)
    await db_session.flush()

    await set_db_context(db_session, org_id=org_id, user_id=user_id)
    org = Organization(
        id=org_id,
        name=f"Intel Org {uuid.uuid4().hex[:6]}",
        slug=f"intel-org-{uuid.uuid4().hex[:6]}",
        status="active",
    )
    db_session.add(org)
    await db_session.flush()

    membership = Membership(
        id=uuid.uuid4(),
        organization_id=org_id,
        user_id=user_id,
        role=Role.SECURITY_LEAD.value,
        status="active",
    )
    db_session.add(membership)

    project = Project(
        id=uuid.uuid4(),
        organization_id=org_id,
        name="Threat Project",
        slug=f"threat-proj-{uuid.uuid4().hex[:6]}",
        criticality="high",
    )
    db_session.add(project)
    await db_session.flush()

    auth_headers = _build_auth_headers(ph9_env, sub, email)

    return {
        "org": org,
        "user": user,
        "membership": membership,
        "project": project,
        "auth_headers": auth_headers,
    }


# ---------------------------------------------------------------------------
# 1. Connector Unit Tests
# ---------------------------------------------------------------------------


def test_cisa_kev_connector_normalization_and_validation() -> None:
    connector = CisaKevConnector()
    sample_payload = {
        "title": "CISA KEV Catalog",
        "catalogVersion": "2026.11.13",
        "vulnerabilities": [
            {
                "cveID": "CVE-2021-44228",
                "vendorProject": "Apache",
                "product": "Log4j",
                "vulnerabilityName": "Remote Code Execution",
                "dateAdded": "2021-12-10",
                "shortDescription": "Apache Log4j JNDI RCE vulnerability",
                "requiredAction": "Apply vendor updates immediately.",
                "dueDate": "2021-12-24",
                "knownRansomwareCampaignUse": "Known",
            }
        ],
    }
    batch = FeedBatch(
        cursor_before=None,
        cursor_after="2026.11.13",
        raw_payload=sample_payload,
        raw_hash="abc",
        retrieved_at=datetime.now(UTC),
        record_count=1,
    )
    val = connector.validate(batch)
    assert val.is_valid is True

    records = connector.normalize(batch)
    assert len(records) == 1
    rec = records[0]
    assert rec.source_record_id == "CVE-2021-44228"
    assert rec.record_type == "kev"
    assert rec.is_known_exploited is True
    assert "Log4j" in (rec.title or "")
    assert len(rec.relationships) == 1
    assert rec.relationships[0].relationship_type == "cve_to_kev"


def test_first_epss_connector_normalization_and_validation() -> None:
    connector = FirstEpssConnector()
    sample_payload = {
        "status": "OK",
        "data": [
            {
                "cve": "CVE-2021-44228",
                "epss": "0.97450",
                "percentile": "0.99980",
                "date": "2026-11-13",
            }
        ],
    }
    batch = FeedBatch(
        cursor_before=None,
        cursor_after="1",
        raw_payload=sample_payload,
        raw_hash="epss_hash",
        retrieved_at=datetime.now(UTC),
        record_count=1,
    )
    val = connector.validate(batch)
    assert val.is_valid is True

    records = connector.normalize(batch)
    assert len(records) == 1
    rec = records[0]
    assert rec.source_record_id == "CVE-2021-44228"
    assert rec.record_type == "epss"
    assert rec.epss_score == pytest.approx(0.9745, rel=1e-3)
    assert rec.epss_percentile == pytest.approx(0.9998, rel=1e-3)
    assert len(rec.relationships) == 1
    assert rec.relationships[0].relationship_type == "cve_to_epss"


def test_nvd_cve_connector_normalization_and_validation() -> None:
    connector = NvdCveConnector()
    sample_payload = {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-44228",
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": (
                                "Apache Log4j2 JNDI features do not protect "
                                "against attacker controlled LDAP."
                            ),
                        }
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                    "baseScore": 10.0,
                                }
                            }
                        ]
                    },
                    "weaknesses": [
                        {
                            "description": [
                                {
                                    "lang": "en",
                                    "value": "CWE-502",
                                }
                            ]
                        }
                    ],
                }
            }
        ],
    }
    batch = FeedBatch(
        cursor_before=None,
        cursor_after="1",
        raw_payload=sample_payload,
        raw_hash="nvd_hash",
        retrieved_at=datetime.now(UTC),
        record_count=1,
    )
    val = connector.validate(batch)
    assert val.is_valid is True

    records = connector.normalize(batch)
    assert len(records) == 1
    rec = records[0]
    assert rec.source_record_id == "CVE-2021-44228"
    assert rec.record_type == "cve"
    assert rec.cvss_score == 10.0
    assert "CVSS:3.1" in (rec.cvss_vector or "")
    assert len(rec.relationships) == 1
    assert rec.relationships[0].relationship_type == "cve_to_cwe"
    assert rec.relationships[0].target_identifier == "CWE-502"


def test_exploit_db_connector_safety_and_normalization() -> None:
    connector = ExploitDbConnector()
    sample_payload = {
        "exploits": [
            {
                "id": "50592",
                "file": "exploits/multiple/remote/50592.py",
                "description": "Apache Log4j 2 - Remote Code Execution (RCE) PoC",
                "date_published": "2021-12-15",
                "author": "kozmer",
                "type": "remote",
                "platform": "multiple",
                "port": "80",
                "codes": "CVE-2021-44228",
            }
        ]
    }
    batch = FeedBatch(
        cursor_before=None,
        cursor_after="1",
        raw_payload=sample_payload,
        raw_hash="edb_hash",
        retrieved_at=datetime.now(UTC),
        record_count=1,
    )
    val = connector.validate(batch)
    assert val.is_valid is True

    records = connector.normalize(batch)
    assert len(records) == 1
    rec = records[0]
    assert rec.source_record_id == "EDB-50592"
    assert rec.record_type == "edb"
    assert "Log4j" in (rec.title or "")
    assert len(rec.relationships) == 1
    assert rec.relationships[0].relationship_type == "cve_to_edb"
    assert rec.relationships[0].target_identifier == "CVE-2021-44228"


def test_gated_connectors_privacy_and_scope_validation() -> None:
    # 1. VirusTotal Privacy Gate
    vt_default = VirusTotalGatedConnector(allow_binary_upload=False)
    # Binary upload hard-blocked by default
    with pytest.raises(PermissionError, match="PRIVACY GATE VIOLATION"):
        vt_default.upload_file_binary("malicious.bin", b"\x90\x90\x90")

    # Hash lookup is allowed (passive lookup, no sensitive upload)
    sample_sha = "2754028350bbec6980d940ee0dd692415054d4d04599e757fed07714ee4bb6a1"
    res = vt_default.lookup_file_hash(sample_sha)
    assert res["reputation"] == "benign"
    assert res["malicious_votes"] == 0

    vt_enabled = VirusTotalGatedConnector(allow_binary_upload=True)
    # Upload without explicit admin approval is blocked
    with pytest.raises(PermissionError, match="Organization Admin authorization"):
        vt_enabled.upload_file_binary("secret.py", b"import secret", admin_approved=False)

    # Upload with admin approval succeeds
    up_res = vt_enabled.upload_file_binary("secret.py", b"import secret", admin_approved=True)
    assert up_res["uploaded"] is True

    # 2. Shodan Scope Gate
    shodan = ShodanGatedConnector()
    with pytest.raises(PermissionError, match="SCOPE GATE VIOLATION"):
        shodan.query_host("unauthorized.target.com", is_in_scope=False)

    shodan_res = shodan.query_host("authorized.target.com", is_in_scope=True)
    assert shodan_res["host"] == "authorized.target.com"
    assert 443 in shodan_res["ports"]


# ---------------------------------------------------------------------------
# 2. Sync Engine & Database Persistence
# ---------------------------------------------------------------------------


async def test_threat_intel_sync_persistence_and_snapshots(db_session: AsyncSession) -> None:
    # 1. Sync CISA KEV
    kev_run = await sync_intelligence_source(db_session, source_slug="cisa_kev")
    assert kev_run.status == "succeeded"

    # 2. Sync EPSS
    epss_run = await sync_intelligence_source(db_session, source_slug="first_epss")
    assert epss_run.status == "succeeded"

    # 3. Sync Exploit-DB
    edb_run = await sync_intelligence_source(db_session, source_slug="exploit_db")
    assert edb_run.status == "succeeded"
    assert edb_run.records_persisted >= 1

    # Verify immutable snapshot was created
    snapshots = (
        (await db_session.execute(select(IntelSnapshot).order_by(IntelSnapshot.created_at.desc())))
        .scalars()
        .all()
    )
    assert len(snapshots) >= 1
    assert snapshots[0].is_stale is False


# ---------------------------------------------------------------------------
# 3. Finding Enrichment & Deterministic Replay
# ---------------------------------------------------------------------------


async def test_finding_enrichment_and_immutable_events(
    db_session: AsyncSession,
    phase9_fixtures: dict[str, Any],
) -> None:
    org = phase9_fixtures["org"]
    user = phase9_fixtures["user"]
    project = phase9_fixtures["project"]

    await set_db_context(db_session, org_id=org.id, user_id=user.id)

    # 1. Populate threat intel record for CVE-2021-44228
    source = (
        await db_session.execute(
            select(IntelligenceSource).where(IntelligenceSource.slug == "cisa_kev")
        )
    ).scalar_one()

    kev_rec = (
        await db_session.execute(
            select(IntelRecord).where(
                IntelRecord.source_id == source.id,
                IntelRecord.source_record_id == "CVE-2021-44228",
            )
        )
    ).scalar_one_or_none()
    if not kev_rec:
        kev_rec = IntelRecord(
            id=uuid.uuid4(),
            source_id=source.id,
            source_record_id="CVE-2021-44228",
            record_type="kev",
            title="Apache Log4j RCE",
            summary="Log4j JNDI execution",
            is_known_exploited=True,
            raw_hash="hash1",
            normalized_hash="norm1",
            retrieved_at=datetime.now(UTC),
        )
        db_session.add(kev_rec)

    epss_source = (
        await db_session.execute(
            select(IntelligenceSource).where(IntelligenceSource.slug == "first_epss")
        )
    ).scalar_one()

    epss_rec = (
        await db_session.execute(
            select(IntelRecord).where(
                IntelRecord.source_id == epss_source.id,
                IntelRecord.source_record_id == "CVE-2021-44228",
            )
        )
    ).scalar_one_or_none()
    if not epss_rec:
        epss_rec = IntelRecord(
            id=uuid.uuid4(),
            source_id=epss_source.id,
            source_record_id="CVE-2021-44228",
            record_type="epss",
            title="EPSS Log4j",
            epss_score=0.9745,
            epss_percentile=0.9998,
            raw_hash="hash2",
            normalized_hash="norm2",
            retrieved_at=datetime.now(UTC),
        )
        db_session.add(epss_rec)

    edb_source = (
        await db_session.execute(
            select(IntelligenceSource).where(IntelligenceSource.slug == "exploit_db")
        )
    ).scalar_one()

    edb_rec = (
        await db_session.execute(
            select(IntelRecord).where(
                IntelRecord.source_id == edb_source.id,
                IntelRecord.source_record_id == "EDB-50592",
            )
        )
    ).scalar_one_or_none()
    if not edb_rec:
        edb_rec = IntelRecord(
            id=uuid.uuid4(),
            source_id=edb_source.id,
            source_record_id="EDB-50592",
            record_type="edb",
            title="Log4j RCE PoC",
            raw_hash="hash3",
            normalized_hash="norm3",
            retrieved_at=datetime.now(UTC),
        )
        db_session.add(edb_rec)
        await db_session.flush()

    rel_res = await db_session.execute(
        select(IntelRelationship).where(
            IntelRelationship.intel_record_id == edb_rec.id,
            IntelRelationship.target_identifier == "CVE-2021-44228",
        )
    )
    rel = rel_res.scalars().first()
    if not rel:
        rel = IntelRelationship(
            id=uuid.uuid4(),
            intel_record_id=edb_rec.id,
            relationship_type="cve_to_edb",
            target_identifier_type="cve",
            target_identifier="CVE-2021-44228",
        )
        db_session.add(rel)

    # 2. Create finding mentioning CVE-2021-44228
    finding = Finding(
        id=uuid.uuid4(),
        organization_id=org.id,
        project_id=project.id,
        fingerprint=f"fp-log4j-{uuid.uuid4().hex[:6]}",
        category="sca",
        scanner_tool_id="grype",
        scanner_version="v0.121.3",
        rule_id="CVE-2021-44228",
        title="Vulnerable Apache Log4j library detected",
        description="Remote code execution in log4j-core via JNDI lookup",
        severity="critical",
        confidence="high",
        validation_status="unverified",
        status="open",
        cve_id="CVE-2021-44228",
        is_known_exploited=False,
    )
    db_session.add(finding)
    await db_session.flush()

    # 3. Execute enrichment
    intel = await enrich_finding_with_intel(db_session, org_id=org.id, finding=finding)
    await db_session.flush()

    assert intel is not None
    assert finding.is_known_exploited is True
    assert float(finding.epss_score or 0) == pytest.approx(0.9745, rel=1e-3)
    assert float(finding.epss_percentile or 0) == pytest.approx(0.9998, rel=1e-3)

    # 4. Verify immutable IntelEnrichmentEvent was recorded
    events = (
        (
            await db_session.execute(
                select(IntelEnrichmentEvent).where(
                    IntelEnrichmentEvent.organization_id == org.id,
                    IntelEnrichmentEvent.finding_id == finding.id,
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(events) == 1
    event = events[0]
    assert event.enrichment_data["is_known_exploited"] is True
    assert len(event.enrichment_data["exploit_references"]) >= 1
    edb_ids = [ref["id"] for ref in event.enrichment_data["exploit_references"]]
    assert "EDB-50592" in edb_ids

    # 5. Verify batch enrichment
    batch_count = await batch_enrich_org_findings(db_session, org_id=org.id)
    assert batch_count >= 1

    # 6. Verify summary
    summary = await get_org_threat_intel_summary(db_session, org_id=org.id)
    assert summary["total_findings"] >= 1
    assert summary["kev_findings_count"] >= 1
    assert summary["high_epss_findings_count"] >= 1
    assert len(summary["sources"]) >= 1


# ---------------------------------------------------------------------------
# 4. REST API Endpoint Tests
# ---------------------------------------------------------------------------


async def test_threat_intel_api_routes(
    ph9_env: dict[str, Any],
) -> None:
    session_factory = ph9_env["session_factory"]
    org_id = uuid.uuid4()
    lead_id = uuid.uuid4()
    sub = f"ph9-lead-{uuid.uuid4().hex[:8]}"
    email = f"lead-{uuid.uuid4().hex[:6]}@example.com"
    project_id = uuid.uuid4()

    async with session_factory() as sess, sess.begin():
        await set_db_context(sess, auth_lookup=(ph9_env["issuer"], sub))
        user = AppUser(
            id=lead_id,
            oidc_issuer=ph9_env["issuer"],
            oidc_subject=sub,
            email=email,
            display_name="Threat Intel Lead",
            status="active",
        )
        sess.add(user)
        await sess.flush()

        await set_db_context(sess, org_id=org_id, user_id=lead_id)
        org = Organization(
            id=org_id,
            name=f"Intel Org {uuid.uuid4().hex[:6]}",
            slug=f"intel-org-{uuid.uuid4().hex[:6]}",
            status="active",
        )
        sess.add(org)
        await sess.flush()

        membership = Membership(
            id=uuid.uuid4(),
            organization_id=org_id,
            user_id=lead_id,
            role=Role.SECURITY_LEAD.value,
            status="active",
        )
        sess.add(membership)

        project = Project(
            id=project_id,
            organization_id=org_id,
            name="Threat Project",
            slug=f"threat-proj-{uuid.uuid4().hex[:6]}",
            criticality="high",
        )
        sess.add(project)
        await sess.flush()

    headers = _build_auth_headers(ph9_env, sub, email)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. GET /api/v1/intel/sources
        resp = await client.get("/api/v1/intel/sources", headers=headers)
        assert resp.status_code == 200
        sources = resp.json()
        assert len(sources) >= 6
        slugs = [s["slug"] for s in sources]
        assert "cisa_kev" in slugs
        assert "first_epss" in slugs
        assert "nvd" in slugs
        assert "exploit_db" in slugs

        # 2. POST /api/v1/intel/sources/exploit_db/sync
        resp = await client.post("/api/v1/intel/sources/exploit_db/sync", headers=headers)
        assert resp.status_code == 200
        sync_run = resp.json()
        assert sync_run["status"] in ("succeeded", "running")

        # 3. GET /api/v1/intel/sources/exploit_db/runs
        resp = await client.get("/api/v1/intel/sources/exploit_db/runs", headers=headers)
        assert resp.status_code == 200
        runs = resp.json()
        assert len(runs) >= 1

        # 4. GET /api/v1/intel/cve/CVE-2021-44228
        resp = await client.get("/api/v1/intel/cve/CVE-2021-44228", headers=headers)
        assert resp.status_code == 200
        cve_intel = resp.json()
        assert cve_intel["cve_id"] == "CVE-2021-44228"

        # 5. POST /api/v1/organizations/{org_id}/findings/enrich
        resp = await client.post(
            f"/api/v1/organizations/{org_id}/findings/enrich",
            json={},
            headers=headers,
        )
        assert resp.status_code == 200
        enrich_res = resp.json()
        assert "enriched_count" in enrich_res

        # 6. GET /api/v1/organizations/{org_id}/intel/summary
        resp = await client.get(
            f"/api/v1/organizations/{org_id}/intel/summary",
            headers=headers,
        )
        assert resp.status_code == 200
        summary = resp.json()
        assert summary["organization_id"] == str(org_id)
        assert "kev_findings_count" in summary


@pytest.mark.asyncio
async def test_intel_snapshots_append_only_trigger(
    db_session: AsyncSession,
) -> None:
    """PostgreSQL trigger prevent_phase9_immutable_mutation rejects UPDATE and DELETE."""
    source_res = await db_session.execute(
        select(IntelligenceSource).where(IntelligenceSource.slug == "cisa_kev")
    )
    source = source_res.scalar_one()

    snap_id = uuid.uuid4()
    tag = f"test-snap-{uuid.uuid4().hex[:8]}"
    snapshot = IntelSnapshot(
        id=snap_id,
        source_id=source.id,
        snapshot_tag=tag,
        snapshot_hash="hash-123",
        record_count=10,
        is_stale=False,
    )
    db_session.add(snapshot)
    await db_session.flush()

    # 1. Attempt UPDATE -> must raise exception (trigger or REVOKE UPDATE)
    with pytest.raises(Exception) as exc_update:
        async with db_session.begin_nested():
            await db_session.execute(
                text("UPDATE intel_snapshots SET record_count = 999 WHERE id = :id"),
                {"id": snap_id},
            )
    err_up = str(exc_update.value).lower()
    assert "append-only" in err_up or "55000" in err_up or "permission denied" in err_up

    # 2. Attempt DELETE -> must raise exception (trigger or REVOKE DELETE)
    with pytest.raises(Exception) as exc_delete:
        async with db_session.begin_nested():
            await db_session.execute(
                text("DELETE FROM intel_snapshots WHERE id = :id"),
                {"id": snap_id},
            )
    err_del = str(exc_delete.value).lower()
    assert "append-only" in err_del or "55000" in err_del or "permission denied" in err_del


@pytest.mark.asyncio
async def test_failed_sync_marks_snapshot_stale(
    db_session: AsyncSession,
) -> None:
    """When a feed synchronization fails, a stale snapshot row is appended."""
    from unittest.mock import AsyncMock, MagicMock

    from vforge.intel.connector import SourceHealth, SourceMetadata

    mock_connector = MagicMock()
    mock_connector.metadata.return_value = SourceMetadata(
        slug="cisa_kev",
        name="CISA KEV",
        source_type="exploit_catalog",
        provider_url="https://cisa.gov",
        license_name="CC0",
    )
    mock_connector.health_check = AsyncMock(
        return_value=SourceHealth(is_healthy=True, status_code=200)
    )
    mock_connector.fetch_incremental = AsyncMock(side_effect=RuntimeError("Feed timeout"))

    run = await sync_intelligence_source(
        db_session, source_slug="cisa_kev", connector_override=mock_connector
    )
    assert run.status == "failed"
    assert "Feed timeout" in (run.error_message or "")

    # Verify that a stale snapshot was appended
    source_res = await db_session.execute(
        select(IntelligenceSource).where(IntelligenceSource.slug == "cisa_kev")
    )
    source = source_res.scalar_one()

    latest_stale = (
        await db_session.execute(
            select(IntelSnapshot)
            .where(IntelSnapshot.source_id == source.id)
            .order_by(IntelSnapshot.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    assert latest_stale is not None
    assert latest_stale.is_stale is True
    assert "Feed timeout" in (latest_stale.stale_reason or "")


@pytest.mark.asyncio
async def test_global_sync_endpoint_requires_admin_role(
    ph9_env: dict[str, Any],
) -> None:
    """Global POST /api/v1/intel/sources/{slug}/sync rejects non-administrative users with 403."""
    session_factory = ph9_env["session_factory"]
    iss = ph9_env["issuer"]
    org_id = uuid.uuid4()
    viewer_id = uuid.uuid4()
    viewer_sub = f"viewer-{uuid.uuid4().hex[:8]}"
    viewer_email = f"viewer-{uuid.uuid4().hex[:6]}@example.com"

    async with session_factory() as sess, sess.begin():
        await set_db_context(sess, auth_lookup=(iss, viewer_sub))
        viewer_user = AppUser(
            id=viewer_id,
            oidc_issuer=iss,
            oidc_subject=viewer_sub,
            email=viewer_email,
            display_name="Viewer User",
            status="active",
        )
        sess.add(viewer_user)
        await sess.flush()

        await set_db_context(sess, org_id=org_id, user_id=viewer_id)
        org = Organization(
            id=org_id,
            name=f"Viewer Org {uuid.uuid4().hex[:6]}",
            slug=f"viewer-org-{uuid.uuid4().hex[:6]}",
            status="active",
        )
        sess.add(org)
        await sess.flush()

        viewer_membership = Membership(
            id=uuid.uuid4(),
            organization_id=org_id,
            user_id=viewer_id,
            role=Role.VIEWER.value,
            status="active",
        )
        sess.add(viewer_membership)
        await sess.flush()

    headers = _build_auth_headers(ph9_env, viewer_sub, viewer_email)
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        resp = await client.post("/api/v1/intel/sources/cisa_kev/sync", headers=headers)
        assert resp.status_code == 403
        assert "administrative role" in resp.json()["detail"].lower()


def test_exposure_detect_query_type_variants_and_validation() -> None:
    """Verify automatic classification of domain, @domain, email, IP, company, and username."""
    from vforge.errors import ValidationError
    from vforge.intel.exposure import detect_query_type

    assert detect_query_type("example.com") == ("domain", "example.com")
    assert detect_query_type("@example.com") == ("domain", "example.com")
    assert detect_query_type("https://dev.example.com/user") == (
        "domain",
        "dev.example.com",
    )
    assert detect_query_type("Admin@Example.com") == (
        "email",
        "admin@example.com",
    )
    assert detect_query_type("93.184.216.34") == ("ip", "93.184.216.34")
    assert detect_query_type("example corp") == ("company", "example corp")
    assert detect_query_type("examplecorp", "username") == (
        "username",
        "examplecorp",
    )

    with pytest.raises(ValidationError):
        detect_query_type("   ")
    with pytest.raises(ValidationError):
        detect_query_type("not-an-ip", "ip")
    with pytest.raises(ValidationError):
        detect_query_type("not a domain", "domain")


@pytest.mark.asyncio
async def test_multi_source_exposure_search_and_finding_import_e2e(
    ph9_env: dict[str, Any],
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify Hudson Rock + free OSINT correlation, redaction, sorting, and finding import."""
    import httpx as httpx_mod

    from vforge.intel.exposure import search_multi_source_exposure

    org_id = uuid.uuid4()
    user_id = uuid.uuid4()
    project_id = uuid.uuid4()
    user_sub = f"osint-owner-{uuid.uuid4().hex[:8]}"
    user_email = f"{user_sub}@example.com"

    session_factory = ph9_env["session_factory"]
    async with session_factory() as sess, sess.begin():
        await set_db_context(sess, auth_lookup=(ph9_env["issuer"], user_sub))
        user = AppUser(
            id=user_id,
            oidc_issuer=ph9_env["issuer"],
            oidc_subject=user_sub,
            email=user_email,
            display_name="OSINT Analyst",
            status="active",
        )
        sess.add(user)
        await sess.flush()

        await set_db_context(sess, org_id=org_id, user_id=user_id)
        org = Organization(
            id=org_id,
            name=f"OSINT Org {uuid.uuid4().hex[:6]}",
            slug=f"osint-org-{uuid.uuid4().hex[:6]}",
            status="active",
        )
        sess.add(org)
        await sess.flush()

        membership = Membership(
            id=uuid.uuid4(),
            organization_id=org_id,
            user_id=user_id,
            role=Role.OWNER.value,
            status="active",
        )
        project = Project(
            id=project_id,
            organization_id=org_id,
            name="Crede Assessment",
            slug="crede-assessment",
        )
        sess.add_all([membership, project])
        await sess.flush()

    await set_db_context(db_session, org_id=org_id, user_id=user_id)

    def mock_osint_handler(request: httpx_mod.Request) -> httpx_mod.Response:
        url_str = str(request.url)
        if "autocomplete.clearbit.com" in url_str:
            return httpx_mod.Response(
                200,
                json=[{"name": "Example Corp", "domain": "example.com"}],
            )
        if "cavalier.hudsonrock.com" in url_str and "search-by-domain" in url_str:
            return httpx_mod.Response(
                200,
                json={
                    "total": 7,
                    "employees": 1,
                    "users": 2,
                    "third_parties": 4,
                    "last_employee_compromised": "2025-06-09T14:56:15.000Z",
                    "last_user_compromised": "2022-09-01T07:14:22.000Z",
                    "stealerFamilies": {"total": 2, "RedLine": 1, "Lumma": 1},
                    "userPasswords": {"weak": {"perc": 32.65}},
                    "data": {
                        "employees_urls": [
                            {
                                "occurrence": 3,
                                "type": "Employee",
                                "url": "https://example.com:2078",
                            }
                        ],
                        "clients_urls": [
                            {
                                "occurrence": 7,
                                "type": "User",
                                "url": "http://onboarding.example.com",
                            }
                        ],
                    },
                    "thirdPartyDomains": [
                        {"domain": "example-partner.org", "occurrence": 3},
                        {"domain": "198.51.100.42", "occurrence": 1},
                    ],
                },
            )
        if "cavalier.hudsonrock.com" in url_str and "search-by-email" in url_str:
            return httpx_mod.Response(
                200,
                json={
                    "stealers": [
                        {
                            "date_compromised": "2025-07-15T10:20:30.000Z",
                            "stealer_family": "Lumma",
                            "computer_name": "DEV-WORKSTATION",
                            "operating_system": "Windows 11 Pro",
                            "ip": "198.51.100.xxx",
                            "total_corporate_services": 2,
                            "total_user_services": 5,
                            "top_passwords": ["SuperSecretRawPass999!"],
                            "top_logins": ["admin@example.com"],
                        }
                    ]
                },
            )
        if "api.proxynova.com/comb" in url_str:
            return httpx_mod.Response(
                200,
                json={
                    "count": 1,
                    "lines": ["admin@example.com:LeakedPlaintextPassword123!"],
                },
            )
        if "api.xposedornot.com" in url_str:
            return httpx_mod.Response(
                200,
                json={
                    "ExposedBreaches": {
                        "breaches_details": [
                            {
                                "breach": "AlienStealerLogs",
                                "domain": "example.com",
                                "xposed_date": "2025-05",
                                "xposed_data": "Email addresses;Passwords",
                                "password_risk": "plaintext",
                            }
                        ]
                    }
                },
            )
        if "api.hackertarget.com/hostsearch" in url_str:
            return httpx_mod.Response(
                200,
                text="example.com,203.0.113.10\nvps.example.com,198.51.100.42\n",
            )
        if "internetdb.shodan.io" in url_str:
            return httpx_mod.Response(
                200,
                json={
                    "ip": "198.51.100.42",
                    "ports": [22, 80, 443, 2083, 2087],
                    "cpes": ["cpe:/a:apache:http_server"],
                    "hostnames": ["vps.example.com"],
                    "tags": ["vpn"],
                    "vulns": ["CVE-2021-44228"],
                },
            )
        if "crt.sh" in url_str:
            return httpx_mod.Response(
                200,
                json=[
                    {
                        "name_value": "dev.example.com\nvps.example.com",
                        "not_before": "2025-06-01T00:00:00",
                    }
                ],
            )
        if "otx.alienvault.com" in url_str:
            return httpx_mod.Response(
                200,
                json={
                    "pulse_info": {
                        "count": 1,
                        "pulses": [
                            {
                                "name": "Lumma Stealer Infrastructure",
                                "modified": "2025-06-12T00:00:00.000Z",
                                "tags": ["lumma", "infostealer"],
                            }
                        ],
                    }
                },
            )
        if "urlscan.io" in url_str:
            return httpx_mod.Response(
                200,
                json={
                    "results": [
                        {
                            "task": {"time": "2025-06-10T12:00:00.000Z"},
                            "page": {
                                "url": "https://dev.example.com/user",
                                "domain": "dev.example.com",
                                "ip": "203.0.113.10",
                                "server": "cloudflare",
                            },
                            "verdicts": {"overall": {"malicious": False}},
                        }
                    ]
                },
            )
        if "web.archive.org" in url_str:
            return httpx_mod.Response(
                200,
                json=[
                    ["timestamp", "original", "mimetype", "statuscode"],
                    [
                        "20250711181730",
                        "https://www.example.com/admin/login",
                        "text/html",
                        "200",
                    ],
                ],
            )
        return httpx_mod.Response(200, json={})

    mock_transport = httpx_mod.MockTransport(mock_osint_handler)
    async with httpx_mod.AsyncClient(transport=mock_transport) as mock_http:
        res = await search_multi_source_exposure(
            db_session,
            org_id=org_id,
            query="example corp",
            query_type="company",
            http_client=mock_http,
        )

    assert res["detected_type"] == "company"
    assert "example.com" in res["resolved_domains"]
    assert "198.51.100.42" in res["resolved_ips"]
    assert "admin@example.com" in res["discovered_emails"]
    assert res["hudson_rock_overview"]["total_hits"] == 7
    assert res["hudson_rock_overview"]["employees_compromised"] == 1
    assert res["critical_count"] >= 2
    assert res["total_records"] >= 8

    # Crucial secret-hygiene assertion: plaintext passwords from COMB or Hudson Rock never appear
    serialized = json.dumps(res, default=str)
    assert "LeakedPlaintextPassword123!" not in serialized
    assert "SuperSecretRawPass999!" not in serialized

    # Chronological sorting assertion: 2025-07-15 record appears before 2022-09-01 record
    dated_records = [r for r in res["records"] if r["occurred_at"] is not None]
    assert len(dated_records) >= 3
    assert dated_records[0]["occurred_at"] >= dated_records[1]["occurred_at"]

    # Test HTTP API endpoints (/intel/exposure-search and /intel/exposure-findings)
    async def patched_search(
        db: AsyncSession,
        *,
        org_id: uuid.UUID,
        query: str,
        query_type: str = "auto",
    ) -> dict[str, Any]:
        async with httpx_mod.AsyncClient(transport=mock_transport) as client_inner:
            return await search_multi_source_exposure(
                db,
                org_id=org_id,
                query=query,
                query_type=query_type,
                http_client=client_inner,
            )

    monkeypatch.setattr("vforge.api.routers.intel.search_multi_source_exposure", patched_search)
    headers = _build_auth_headers(ph9_env, user_sub, user_email)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        search_resp = await client.post(
            f"/api/v1/organizations/{org_id}/intel/exposure-search",
            headers=headers,
            json={"query": "@example.com", "query_type": "auto"},
        )
        assert search_resp.status_code == 200
        search_data = search_resp.json()
        assert search_data["detected_type"] == "domain"
        assert search_data["normalized_query"] == "example.com"
        first_rec = search_data["records"][0]

        # Promote exposure record to tracked project Finding
        imp_resp = await client.post(
            f"/api/v1/organizations/{org_id}/intel/exposure-findings",
            headers=headers,
            json={
                "project_id": str(project_id),
                "source_slug": first_rec["source_slug"],
                "category": first_rec["category"],
                "severity": first_rec["severity"],
                "title": first_rec["title"],
                "target": first_rec["target"],
                "summary": first_rec["summary"],
                "remediation": first_rec["remediation"],
                "cve_id": first_rec["cve_id"],
            },
        )
        assert imp_resp.status_code == 201
        imp_data = imp_resp.json()
        assert imp_data["created"] is True
        assert imp_data["project_id"] == str(project_id)

        # Second import of identical record is idempotent (created=False)
        imp_resp_2 = await client.post(
            f"/api/v1/organizations/{org_id}/intel/exposure-findings",
            headers=headers,
            json={
                "project_id": str(project_id),
                "source_slug": first_rec["source_slug"],
                "category": first_rec["category"],
                "severity": first_rec["severity"],
                "title": first_rec["title"],
                "target": first_rec["target"],
                "summary": first_rec["summary"],
                "remediation": first_rec["remediation"],
                "cve_id": first_rec["cve_id"],
            },
        )
        assert imp_resp_2.status_code == 201
        assert imp_resp_2.json()["created"] is False
        assert imp_resp_2.json()["finding_id"] == imp_data["finding_id"]

"""Tenant-isolated RAG ingestion and retrieval over curated approved knowledge sources."""

from __future__ import annotations

import hashlib
import re
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.ai_gateway.classification import classify_and_redact_payload
from vforge.errors import ConflictError, ValidationError
from vforge.models.ai_governance import AiAuditEvent, KnowledgeChunk, KnowledgeDocument
from vforge.models.enums import AiAuditAction, KnowledgeSourceType

_APPROVED_SOURCE_TYPES = frozenset(m.value for m in KnowledgeSourceType)
_ALLOWED_URI_PREFIXES = ("curated://", "https://")
_TOKEN_RE = re.compile(r"[a-z0-9_.-]{3,}")


def _chunk_text(raw_content: str, *, chunk_size: int = 800) -> list[str]:
    text = raw_content.strip()
    if not text:
        return []
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
    chunks: list[str] = []
    current = ""
    for para in paragraphs:
        if len(para) > chunk_size:
            if current:
                chunks.append(current)
                current = ""
            for i in range(0, len(para), chunk_size):
                chunks.append(para[i : i + chunk_size])
            continue
        candidate = f"{current}\n\n{para}" if current else para
        if len(candidate) <= chunk_size:
            current = candidate
        else:
            chunks.append(current)
            current = para
    if current:
        chunks.append(current)
    return chunks


async def index_knowledge_document(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    slug: str,
    title: str,
    source_type: str,
    source_uri: str,
    content: str,
    actor_id: uuid.UUID,
    actor_email: str,
) -> KnowledgeDocument:
    """Ingest and chunk an approved security reference strictly within tenant scope."""
    if source_type not in _APPROVED_SOURCE_TYPES:
        raise ValidationError(
            f"Unsupported knowledge source_type '{source_type}'. Only curated approved "
            f"sources are permitted: {sorted(_APPROVED_SOURCE_TYPES)}"
        )
    clean_uri = source_uri.strip()
    if not clean_uri.startswith(_ALLOWED_URI_PREFIXES):
        raise ValidationError("Knowledge source_uri must use 'curated://' or 'https://' scheme")
    clean_slug = slug.strip().lower()
    cls_res = classify_and_redact_payload(content)
    chunks = _chunk_text(cls_res.redacted_text)
    if not chunks:
        raise ValidationError("Knowledge document content must not be empty")

    doc = KnowledgeDocument(
        id=uuid.uuid4(),
        organization_id=organization_id,
        slug=clean_slug,
        title=title.strip(),
        source_type=source_type,
        source_uri=clean_uri,
        content_sha256=hashlib.sha256(cls_res.redacted_text.encode("utf-8")).hexdigest(),
        is_approved=True,
        uploaded_by=actor_id,
    )
    try:
        async with db.begin_nested():
            db.add(doc)
            await db.flush()
    except IntegrityError as exc:
        raise ConflictError(f"Knowledge document slug '{clean_slug}' already exists") from exc

    for idx, chunk in enumerate(chunks):
        keywords = sorted(set(_TOKEN_RE.findall(chunk.lower())))[:25]
        db.add(
            KnowledgeChunk(
                id=uuid.uuid4(),
                organization_id=organization_id,
                document_id=doc.id,
                chunk_index=idx,
                chunk_text=chunk,
                keywords_json=keywords,
                chunk_sha256=hashlib.sha256(chunk.encode("utf-8")).hexdigest(),
            )
        )

    db.add(
        AiAuditEvent(
            id=uuid.uuid4(),
            organization_id=organization_id,
            action=AiAuditAction.KNOWLEDGE_INDEXED.value,
            actor_id=actor_id,
            actor_email=actor_email,
            details_json={
                "document_id": str(doc.id),
                "slug": doc.slug,
                "source_type": source_type,
                "chunk_count": len(chunks),
                "redaction_applied": cls_res.redaction_applied,
            },
        )
    )
    await db.flush()
    return doc


async def retrieve_tenant_knowledge(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    query: str,
    limit: int = 4,
) -> list[dict[str, Any]]:
    """Retrieve approved curated RAG chunks strictly scoped to the caller's organization_id."""
    q_tokens = set(_TOKEN_RE.findall(query.lower()))
    stmt = (
        select(KnowledgeChunk, KnowledgeDocument)
        .join(
            KnowledgeDocument,
            (KnowledgeDocument.organization_id == KnowledgeChunk.organization_id)
            & (KnowledgeDocument.id == KnowledgeChunk.document_id),
        )
        .where(
            KnowledgeChunk.organization_id == organization_id,
            KnowledgeDocument.organization_id == organization_id,
            KnowledgeDocument.is_approved.is_(True),
        )
    )
    rows = (await db.execute(stmt)).all()
    scored: list[tuple[int, KnowledgeChunk, KnowledgeDocument]] = []
    for chunk, doc in rows:
        chunk_terms = set(chunk.keywords_json or []) | set(
            _TOKEN_RE.findall(chunk.chunk_text.lower())
        )
        overlap = len(q_tokens & chunk_terms) if q_tokens else 1
        if overlap > 0 or not q_tokens:
            scored.append((overlap, chunk, doc))

    scored.sort(key=lambda item: (-item[0], item[1].chunk_index))
    return [
        {
            "document_id": str(doc.id),
            "slug": doc.slug,
            "title": doc.title,
            "source_type": doc.source_type,
            "source_uri": doc.source_uri,
            "chunk_id": str(chunk.id),
            "chunk_index": chunk.chunk_index,
            "chunk_sha256": chunk.chunk_sha256,
            "score": score,
            "excerpt": chunk.chunk_text,
        }
        for score, chunk, doc in scored[:limit]
    ]

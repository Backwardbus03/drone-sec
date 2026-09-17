"""
Forensic Ingestion Pipeline for DFT RAG Subsystem.
Extracts, chunks, embeds, and indexes case evidence into an isolated ChromaDB collection.
"""

from typing import List, Dict, Any, Optional
from dft.core.models import (
    FlightEvent, GeofenceViolation, AnomalyReport, TelemetryPoint,
    AuditLogEntry, EvidenceItem, MediaCapture, GCSAnalysisResult,
    MobileCompanionAnalysisResult
)
from dft.rag.chunker import (
    chunk_flight_events,
    chunk_geofence_violations,
    chunk_anomalies,
    chunk_telemetry_windows,
    chunk_audit_log,
    chunk_evidence_items,
    chunk_media_captures,
    chunk_gcs_data,
    chunk_mobile_artifacts
)
from dft.rag.regulations import get_regulation_chunks, get_cached_regulation_chunks_and_embeddings
from dft.rag.embedder import embed
from dft.rag.vector_store import upsert_chunks, count_case_chunks


def ingest_case(
    case_id: str,
    *,
    events: Optional[List[FlightEvent]] = None,
    violations: Optional[List[GeofenceViolation]] = None,
    anomalies: Optional[List[AnomalyReport]] = None,
    telemetry: Optional[List[TelemetryPoint]] = None,
    audit_log: Optional[List[AuditLogEntry]] = None,
    evidence: Optional[List[EvidenceItem]] = None,
    media: Optional[List[MediaCapture]] = None,
    gcs: Optional[GCSAnalysisResult] = None,
    mobile: Optional[MobileCompanionAnalysisResult] = None,
    include_regulations: bool = True
) -> int:
    """
    Ingests all available forensic evidence for a specific case into its isolated vector index.
    Optimizes chunk volume and uses cached regulation embeddings to avoid rate limits.
    Returns total number of chunks indexed.
    """
    case_evidence_chunks: List[Dict[str, Any]] = []

    if events:
        case_evidence_chunks.extend(chunk_flight_events(events, case_id))

    if violations:
        case_evidence_chunks.extend(chunk_geofence_violations(violations, case_id))

    if anomalies:
        case_evidence_chunks.extend(chunk_anomalies(anomalies, case_id))

    if telemetry:
        case_evidence_chunks.extend(chunk_telemetry_windows(telemetry, case_id, window_size=60))

    if audit_log:
        case_evidence_chunks.extend(chunk_audit_log(audit_log, case_id))

    if evidence:
        case_evidence_chunks.extend(chunk_evidence_items(evidence, case_id))

    if media:
        case_evidence_chunks.extend(chunk_media_captures(media, case_id))

    if gcs:
        case_evidence_chunks.extend(chunk_gcs_data(gcs, case_id))

    if mobile:
        case_evidence_chunks.extend(chunk_mobile_artifacts(mobile, case_id))

    all_chunks: List[Dict[str, Any]] = []
    all_embeddings: List[List[float]] = []

    # 1. Embed dynamic case evidence with sliding-window rate limiting
    if case_evidence_chunks:
        texts = [c["text"] for c in case_evidence_chunks]
        evidence_embeddings = embed(texts)
        all_chunks.extend(case_evidence_chunks)
        all_embeddings.extend(evidence_embeddings)

    # 2. Attach pre-cached regulation chunks & embeddings (avoids burning API quota)
    if include_regulations:
        reg_chunks, reg_embeddings = get_cached_regulation_chunks_and_embeddings(case_id)
        all_chunks.extend(reg_chunks)
        all_embeddings.extend(reg_embeddings)

    if not all_chunks:
        return 0

    # Persist in vector store (Pinecone namespace)
    upsert_chunks(case_id, all_chunks, all_embeddings)

    return len(all_chunks)


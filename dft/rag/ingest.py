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
from dft.rag.regulations import get_regulation_chunks
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
    Returns total number of chunks indexed.
    """
    all_chunks: List[Dict[str, Any]] = []

    if events:
        all_chunks.extend(chunk_flight_events(events, case_id))

    if violations:
        all_chunks.extend(chunk_geofence_violations(violations, case_id))

    if anomalies:
        all_chunks.extend(chunk_anomalies(anomalies, case_id))

    if telemetry:
        all_chunks.extend(chunk_telemetry_windows(telemetry, case_id, window_size=30))

    if audit_log:
        all_chunks.extend(chunk_audit_log(audit_log, case_id))

    if evidence:
        all_chunks.extend(chunk_evidence_items(evidence, case_id))

    if media:
        all_chunks.extend(chunk_media_captures(media, case_id))

    if gcs:
        all_chunks.extend(chunk_gcs_data(gcs, case_id))

    if mobile:
        all_chunks.extend(chunk_mobile_artifacts(mobile, case_id))

    if include_regulations:
        reg_chunks = get_regulation_chunks()
        for r in reg_chunks:
            r["metadata"]["case_id"] = case_id
        all_chunks.extend(reg_chunks)

    if not all_chunks:
        return 0

    # Compute dense embeddings in batches
    texts = [c["text"] for c in all_chunks]
    embeddings = embed(texts)

    # Persist in ChromaDB collection
    upsert_chunks(case_id, all_chunks, embeddings)

    return len(all_chunks)

"""
Automated Test Suite for Drone Forensic Toolkit RAG Subsystem.
Validates chunking, dense embeddings, isolated case vector collections in ChromaDB,
offline/online LLM fallback, and FastAPI endpoints.
"""

import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from dft.core.models import (
    FlightEvent, GeofenceViolation, AnomalyReport, TelemetryPoint,
    AuditLogEntry, EvidenceItem, HashManifest
)
from dft.rag.chunker import (
    chunk_flight_events, chunk_geofence_violations, chunk_anomalies,
    chunk_telemetry_windows, chunk_audit_log, chunk_evidence_items
)
from dft.rag.embedder import embed, get_embedding_dimension
from dft.rag.vector_store import (
    get_case_collection, upsert_chunks, query_case_vector_store,
    count_case_chunks, delete_case_collection
)
from dft.rag.ingest import ingest_case
from dft.rag.query import answer_case_question
from dft.rag.llm import chat_completion
from dft.api.app import app


@pytest.fixture
def client():
    return TestClient(app)


def test_chunker_models():
    case_id = "TEST_CASE_CHUNKS"
    now_str = datetime.now(timezone.utc).isoformat()

    ev = FlightEvent(
        event_id="EV-01",
        timestamp_utc=now_str,
        event_type="ARM",
        severity="INFO",
        description="Motors armed successfully in GUIDED mode",
        latitude=19.0760,
        longitude=72.8777,
        altitude_m=10.5
    )
    ev_chunks = chunk_flight_events([ev], case_id)
    assert len(ev_chunks) == 1
    assert "Motors armed successfully" in ev_chunks[0]["text"]
    assert ev_chunks[0]["metadata"]["chunk_type"] == "flight_event"

    vio = GeofenceViolation(
        violation_id="VIO-01",
        zone_id="ZONE-MUMBAI-AIRPORT",
        zone_name="Chhatrapati Shivaji Maharaj International Airport",
        timestamp_utc=now_str,
        latitude=19.0896,
        longitude=72.8656,
        altitude_m=120.0,
        violation_type="BOUNDARY_ENTRY",
        severity="CRITICAL",
        details="Unauthorized drone flight in Red Zone airspace (0m ceiling).",
        category="AIRPORT",
        authority="DGCA / AAI"
    )
    vio_chunks = chunk_geofence_violations([vio], case_id)
    assert len(vio_chunks) == 1
    assert "Chhatrapati Shivaji Maharaj" in vio_chunks[0]["text"]
    assert vio_chunks[0]["metadata"]["violation_type"] == "BOUNDARY_ENTRY"

    anom = AnomalyReport(
        anomaly_id="ANOM-01",
        anomaly_type="GPS_DISCORDANCE",
        severity="HIGH",
        description="Secondary GPS discordant by > 15m from primary EKF fix."
    )
    anom_chunks = chunk_anomalies([anom], case_id)
    assert len(anom_chunks) == 1
    assert "GPS_DISCORDANCE" in anom_chunks[0]["text"]


def test_embedder():
    texts = ["Drone takeoff at 14:00 UTC", "Restricted airport airspace breach"]
    vectors = embed(texts)
    assert len(vectors) == 2
    dim = get_embedding_dimension()
    assert len(vectors[0]) == dim
    assert len(vectors[1]) == dim


def test_isolated_case_vector_store():
    case_id = "TEST_VAULT_ISOLATION_01"
    delete_case_collection(case_id)

    # Ingest test chunks
    chunks = [
        {
            "text": "Drone breached Mumbai Airport airspace at 14:22:15 UTC at 85 meters altitude.",
            "metadata": {"case_id": case_id, "chunk_type": "geofence_violation", "severity": "CRITICAL"}
        },
        {
            "text": "Normal cruise telemetry logged with battery at 88%.",
            "metadata": {"case_id": case_id, "chunk_type": "telemetry_window", "severity": "INFO"}
        }
    ]
    vecs = embed([c["text"] for c in chunks])
    upsert_chunks(case_id, chunks, vecs)

    assert count_case_chunks(case_id) == 2

    # Query vector store for airport breach
    q_vec = embed(["Did the drone fly near an airport?"])[0]
    res = query_case_vector_store(case_id, q_vec, top_k=1)
    docs = res["documents"][0]
    assert len(docs) == 1
    assert "Mumbai Airport" in docs[0]

    delete_case_collection(case_id)


def test_ingest_and_query_pipeline():
    case_id = "TEST_RAG_PIPELINE"
    delete_case_collection(case_id)

    events = [
        FlightEvent(
            event_id="E-01",
            timestamp_utc="2026-03-12T14:10:00Z",
            event_type="TAKEOFF",
            description="Takeoff initiated from suspect hideout coordinates.",
            latitude=19.1234,
            longitude=72.9001,
            altitude_m=2.0
        ),
        FlightEvent(
            event_id="E-02",
            timestamp_utc="2026-03-12T14:25:00Z",
            event_type="GEOFENCE_BREACH",
            severity="CRITICAL",
            description="Drone entered BARC Strategic Nuclear exclusion zone.",
            latitude=19.0050,
            longitude=72.9200,
            altitude_m=95.0
        )
    ]

    indexed_count = ingest_case(case_id, events=events, include_regulations=True)
    assert indexed_count > 2  # Includes events + regulation standards

    # Test asking questions
    result = answer_case_question(case_id, "Was there any flight breach near a nuclear or strategic site?")
    assert "answer" in result
    assert result["chunks_retrieved"] > 0
    assert len(result["sources"]) > 0

    # Ensure isolation: checking clean up
    delete_case_collection(case_id)


def test_rag_api_endpoints(client):
    case_id = "TEST_API_RAG_CASE"

    # Create case
    client.post("/api/cases", json={
        "case_id": case_id,
        "case_name": "RAG API Verification Case",
        "investigator_name": "Inspector Sharma",
        "agency_name": "Central Forensic Science Laboratory"
    })

    # Ingest into case RAG
    ingest_res = client.post(f"/api/cases/{case_id}/rag/ingest")
    assert ingest_res.status_code == 200
    data = ingest_res.json()
    assert data["status"] == "INGEST_SUCCESS"

    # Status check
    status_res = client.get(f"/api/cases/{case_id}/rag/status")
    assert status_res.status_code == 200
    st_data = status_res.json()
    assert st_data["case_id"] == case_id
    assert st_data["ready"] is True

    # Query endpoint
    ask_res = client.post(f"/api/cases/{case_id}/ask", json={
        "question": "What standard governs digital evidence acquisition in this case?",
        "top_k": 5
    })
    assert ask_res.status_code == 200
    ask_data = ask_res.json()
    assert "answer" in ask_data
    assert "sources" in ask_data
    assert "provider" in ask_data

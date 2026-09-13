"""
FastAPI End-to-End API and Web Integration Tests for Drone Forensic Toolkit.
"""

import pytest
from fastapi.testclient import TestClient
from dft.api.app import app

client = TestClient(app)


def test_root_dashboard_endpoints():
    response = client.get("/")
    assert response.status_code == 200
    assert "DRONE FORENSIC TOOLKIT" in response.text

    dash_resp = client.get("/dashboard")
    assert dash_resp.status_code == 200
    assert "Flight Trajectory" in dash_resp.text


def test_system_health():
    res = client.get("/api/system/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "HEALTHY"
    assert data["plugins_count"] >= 5


def test_case_lifecycle_and_evidence_ingest():
    # 1. Create Case
    case_payload = {
        "case_id": "API-TEST-CASE-99",
        "case_name": "Airspace Intrusion Investigation",
        "investigator_name": "Senior Forensic Analyst",
        "agency_name": "Cyber Defense Forensics Command",
        "description": "Integration test for API pipeline"
    }
    create_res = client.post("/api/cases", json=case_payload)
    assert create_res.status_code == 200
    assert create_res.json()["case_id"] == "API-TEST-CASE-99"

    # 2. Ingest Evidence (DJI sample)
    with open("samples/dji_mavic3_telemetry.srt", "rb") as f:
        ingest_res = client.post(
            "/api/cases/API-TEST-CASE-99/ingest",
            files={"file": ("dji_mavic3_telemetry.srt", f, "text/plain")},
            data={"acquisition_type": "LOGICAL_EXTRACT", "actor": "QA Automation"}
        )
    assert ingest_res.status_code == 200
    ingest_data = ingest_res.json()
    assert ingest_data["platform_detected"] == "dji"
    assert ingest_data["telemetry_points_extracted"] >= 5

    # 3. Fetch Telemetry and GeoJSON
    geo_res = client.get("/api/cases/API-TEST-CASE-99/geojson")
    assert geo_res.status_code == 200
    assert geo_res.json()["type"] == "FeatureCollection"

    # 4. Add Custom Geofence Zone
    zone_payload = {
        "name": "Target Restricted Area",
        "zone_type": "circle",
        "center_lat": 19.1350,
        "center_lon": 72.9150,
        "radius_meters": 200.0,
        "max_altitude_m": 50.0,
        "description": "Exclusion circle around sensitive facility"
    }
    zone_res = client.post("/api/cases/API-TEST-CASE-99/geofence/zones", json=zone_payload)
    assert zone_res.status_code == 200
    assert zone_res.json()["total_zones"] >= 1

    # 5. Check Violations
    vio_res = client.get("/api/cases/API-TEST-CASE-99/geofence/violations")
    assert vio_res.status_code == 200

    # 6. Check Timeline
    time_res = client.get("/api/cases/API-TEST-CASE-99/timeline")
    assert time_res.status_code == 200
    assert len(time_res.json()) >= 2

    # 7. Check Audit Trail
    audit_res = client.get("/api/cases/API-TEST-CASE-99/audit-trail")
    assert audit_res.status_code == 200
    assert len(audit_res.json()) >= 2

    # 8. Check Reports
    html_rep = client.get("/api/cases/API-TEST-CASE-99/report/html")
    assert html_rep.status_code == 200
    assert "UAV DIGITAL FORENSIC EXAMINATION REPORT" in html_rep.text

    json_rep = client.get("/api/cases/API-TEST-CASE-99/report/json")
    assert json_rep.status_code == 200
    assert "evidence_items" in json_rep.json()

    kml_rep = client.get("/api/cases/API-TEST-CASE-99/kml")
    assert kml_rep.status_code == 200
    assert "<kml" in kml_rep.text

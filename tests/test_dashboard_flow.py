"""
End-to-End API and Static Asset Tests for the Modular Dashboard & Ingestion Workflow.
"""

from pathlib import Path
from fastapi.testclient import TestClient
from dft.api.app import app

client = TestClient(app)


def test_dashboard_and_static_files():
    """Verify that dashboard.html is served and references all modular script and style assets."""
    dash = client.get("/dashboard")
    assert dash.status_code == 200
    assert "DRONE FORENSIC TOOLKIT" in dash.text
    assert "ingestionWizardBanner" in dash.text
    assert "droneLogsSection" in dash.text
    assert "mediaSection" in dash.text

    # Check modular asset endpoints
    assets = [
        "/static/css/styles.css",
        "/static/js/map.js",
        "/static/js/geofence.js",
        "/static/js/evidence.js",
        "/static/js/media.js",
        "/static/js/gcs.js",
        "/static/js/timeline.js",
        "/static/js/reports.js",
        "/static/js/wizard.js",
        "/static/js/app.js"
    ]
    for asset in assets:
        res = client.get(asset)
        assert res.status_code == 200, f"Asset {asset} failed with {res.status_code}"
        assert len(res.content) > 0


def test_guided_ingestion_workflow_backend_sequence():
    """
    Validates the 3-step workflow lifecycle:
    1. Case creation
    2. Step 1: GCS ingestion (tested with sample mission plan)
    3. Step 2: Primary drone log ingestion (mandatory)
    4. Step 3: Payload media ingestion (tested with video)
    """
    case_id = "FLOW-TEST-2026"
    case_res = client.post("/api/cases", json={
        "case_id": case_id,
        "case_name": "Guided Workflow Audit Case",
        "investigator_name": "Lead Forensic Examiner",
        "agency_name": "Digital Forensics Unit",
        "description": "Integration test for 3-step ingestion flow"
    })
    assert case_res.status_code == 200
    assert case_res.json()["case_id"] == case_id

    # Step 1: GCS Ingestion (e.g. QGC survey plan)
    qgc_sample = Path("samples/px4_survey.plan")
    if qgc_sample.exists():
        with open(qgc_sample, "rb") as f:
            gcs_res = client.post(
                f"/api/cases/{case_id}/ingest",
                files={"file": ("px4_survey.plan", f, "application/json")},
                data={"acquisition_type": "LOGICAL_EXTRACT", "actor": "Forensic Investigator"}
            )
        assert gcs_res.status_code == 200
        gcs_data = gcs_res.json()
        assert gcs_data["platform_detected"].lower() in ["qgroundcontrol", "gcs", "px4", "ardupilot"]

    # Step 2: Primary Drone Logs (Mandatory flight telemetry)
    bin_sample = Path("samples/ardupilot_flight.log")
    if bin_sample.exists():
        with open(bin_sample, "rb") as f:
            drone_res = client.post(
                f"/api/cases/{case_id}/ingest",
                files={"file": ("ardupilot_flight.log", f, "text/plain")},
                data={"acquisition_type": "LOGICAL_EXTRACT", "actor": "Forensic Investigator"}
            )
        assert drone_res.status_code == 200
        drone_data = drone_res.json()
        assert drone_data["platform_detected"].lower() == "ardupilot"

    # Step 3: Payload Media Ingestion (Visual evidence)
    video_sample = Path("samples/sample_recon_video.mp4")
    if video_sample.exists():
        with open(video_sample, "rb") as f:
            media_res = client.post(
                f"/api/cases/{case_id}/ingest-media",
                files={"file": ("sample_recon_video.mp4", f, "video/mp4")},
                data={"actor": "Forensic Investigator"}
            )
        assert media_res.status_code == 200
        media_data = media_res.json()
        assert media_data["media_item"]["media_type"] == "VIDEO"

    # Verify finalized case summary
    summary_res = client.get(f"/api/cases/{case_id}/summary")
    assert summary_res.status_code == 200
    summary = summary_res.json()
    case_info = client.get(f"/api/cases/{case_id}").json()
    assert case_info["chain_of_custody_verified"] is True

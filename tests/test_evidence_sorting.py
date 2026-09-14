"""
Automated tests for Evidence Classification, Folder Sorting (Logs, Video/Images, GCS),
Wireless Mobile Upload Multi-Pipeline, and Real-Time Synchronization.
"""

import json
import io
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from dft.api.app import app, BASE_DATA_DIR, CASES_STORE, CASE_EVIDENCE, CASE_TELEMETRY, CASE_MEDIA, CASE_GCS_DATA
from dft.core.classifier import EvidenceClassifier
from dft.core.models import EvidenceItem


client = TestClient(app)


def test_evidence_classifier_by_extension_and_content():
    """Verify that EvidenceClassifier accurately categorizes logs, video/images, and GCS."""
    # 1. Logs
    assert EvidenceClassifier.classify("ardupilot.bin") == "LOGS"
    assert EvidenceClassifier.classify("px4_log.ulg") == "LOGS"
    assert EvidenceClassifier.classify("flight_record.dat") == "LOGS"
    assert EvidenceClassifier.classify("telemetry.srt") == "LOGS"
    assert EvidenceClassifier.classify("litchi_flight.csv") == "LOGS"
    assert EvidenceClassifier.classify("blackbox.bbl") == "LOGS"
    assert EvidenceClassifier.classify("backup.zip") == "LOGS"

    # 2. Video / Images
    assert EvidenceClassifier.classify("drone_cam.mp4") == "VIDEO_IMAGES"
    assert EvidenceClassifier.classify("gimbal_record.mov") == "VIDEO_IMAGES"
    assert EvidenceClassifier.classify("aerial_photo.jpg") == "VIDEO_IMAGES"
    assert EvidenceClassifier.classify("thermal_scan.png") == "VIDEO_IMAGES"
    assert EvidenceClassifier.classify("raw_frame.dng") == "VIDEO_IMAGES"
    assert EvidenceClassifier.classify("media_evidence.eo1") == "VIDEO_IMAGES"

    # JPEG magic bytes
    jpeg_header = b"\xff\xd8\xff\xe0\x00\x10JFIF"
    assert EvidenceClassifier.classify("unknown_blob", content_sample=jpeg_header) == "VIDEO_IMAGES"

    # PNG magic bytes
    png_header = b"\x89PNG\r\n\x1a\n"
    assert EvidenceClassifier.classify("capture.raw", content_sample=png_header) == "VIDEO_IMAGES"

    # 3. Ground Control Station (GCS)
    assert EvidenceClassifier.classify("survey_mission.plan") == "GCS"
    assert EvidenceClassifier.classify("flight_path.waypoints") == "GCS"
    assert EvidenceClassifier.classify("mission.wpl") == "GCS"
    assert EvidenceClassifier.classify("telemetry_stream.tlog") == "GCS"
    assert EvidenceClassifier.classify("boundary.kml") == "GCS"
    assert EvidenceClassifier.classify("dji_route.wpml") == "GCS"

    # QGC header sample
    qgc_header = b"#QGC WPL 110\r\n0\t1\t0\t16\t0\t0\t0\t0\t19.13\t72.91\t50\t1"
    assert EvidenceClassifier.classify("mission.txt", content_sample=qgc_header) == "GCS"


def test_evidence_subfolder_mapping():
    """Verify filesystem folder mapping and UI display badges for each category."""
    assert EvidenceClassifier.get_category_folder("LOGS") == "logs"
    assert EvidenceClassifier.get_category_folder("VIDEO_IMAGES") == "video_images"
    assert EvidenceClassifier.get_category_folder("GCS") == "gcs"

    badge_logs = EvidenceClassifier.get_category_badge("LOGS")
    assert badge_logs["icon"] == "📋"
    assert "amber" in badge_logs["badge_class"]

    badge_media = EvidenceClassifier.get_category_badge("VIDEO_IMAGES")
    assert badge_media["icon"] == "🎥"
    assert "purple" in badge_media["badge_class"]

    badge_gcs = EvidenceClassifier.get_category_badge("GCS")
    assert badge_gcs["icon"] == "🎮"
    assert "sky" in badge_gcs["badge_class"]


def test_file_upload_disk_folder_sorting():
    """Verify that files uploaded to /ingest are saved in segregated subfolders on disk."""
    case_id = "SORT-CASE-01"
    create_res = client.post("/api/cases", json={
        "case_id": case_id,
        "case_name": "Folder Sorting Verification",
        "investigator_name": "Det. Analyst",
        "agency_name": "Digital Forensics Unit"
    })
    assert create_res.status_code == 200

    # 1. Upload a drone flight log (SRT) -> must go to logs/
    with open("samples/dji_mavic3_telemetry.srt", "rb") as f:
        log_res = client.post(
            f"/api/cases/{case_id}/ingest",
            files={"file": ("flight_telemetry.srt", f, "text/plain")},
            data={"acquisition_type": "LOGICAL_EXTRACT", "actor": "Forensic Officer"}
        )
    assert log_res.status_code == 200
    log_data = log_res.json()
    assert log_data["evidence_category"] == "LOGS"
    assert log_data["category_folder"] == "logs"

    stored_log_path = BASE_DATA_DIR / case_id / "logs" / "flight_telemetry.srt"
    assert stored_log_path.exists()

    # 2. Upload a GCS mission plan -> must go to gcs/
    qgc_plan_content = json.dumps({
        "fileType": "Plan",
        "version": 1,
        "groundStation": "QGroundControl",
        "mission": {
            "cruiseSpeed": 15,
            "hoverSpeed": 5,
            "items": [
                {
                    "autoContinue": True,
                    "command": 16,
                    "coordinate": [19.1334, 72.9133, 50.0],
                    "type": "SimpleItem"
                }
            ],
            "plannedHomePosition": [19.1330, 72.9130, 10.0]
        }
    })
    gcs_res = client.post(
        f"/api/cases/{case_id}/ingest",
        files={"file": ("autonomous_survey.plan", qgc_plan_content.encode("utf-8"), "application/json")},
        data={"acquisition_type": "LOGICAL_EXTRACT", "actor": "GCS Analyst"}
    )
    assert gcs_res.status_code == 200
    gcs_data = gcs_res.json()
    assert gcs_data["evidence_category"] == "GCS"
    assert gcs_data["category_folder"] == "gcs"

    stored_gcs_path = BASE_DATA_DIR / case_id / "gcs" / "autonomous_survey.plan"
    assert stored_gcs_path.exists()


def test_wireless_mobile_upload_runs_all_pipelines_and_syncs():
    """
    Verify that evidence uploaded wirelessly from a mobile phone:
    1. Triggers full telemetry parsing (extracts telemetry points into CASE_TELEMETRY).
    2. Sorts into designated category subfolders on disk.
    3. Records a WirelessTransferSession ledger entry.
    4. Bumps case sync version so laptop UI detects it via /sync-status.
    """
    case_id = "MOBILE-SYNC-CASE-02"
    client.post("/api/cases", json={
        "case_id": case_id,
        "case_name": "Mobile Wireless Live Sync Test",
        "investigator_name": "Field Officer",
        "agency_name": "Drone Recovery Taskforce"
    })

    # Initial sync status
    init_sync = client.get(f"/api/cases/{case_id}/sync-status").json()
    initial_ver = init_sync["sync_version"]
    assert init_sync["evidence_count"] == 0
    assert init_sync["telemetry_count"] == 0

    # Suspect phone wirelessly uploads a flight log (.srt)
    with open("samples/dji_mavic3_telemetry.srt", "rb") as f:
        mob_upload_res = client.post(
            f"/api/cases/{case_id}/wireless/upload-mobile",
            files={"file": ("phone_saved_flight.srt", f, "text/plain")},
            data={"actor": "Suspect Phone Wirelessly Connected"}
        )
    assert mob_upload_res.status_code == 200
    mob_data = mob_upload_res.json()

    assert mob_data["status"] == "SUCCESS"
    assert mob_data["evidence_category"] == "LOGS"
    assert mob_data["category_folder"] == "logs"
    assert mob_data["telemetry_points_extracted"] >= 5

    # File must be sorted into logs/ subfolder
    assert (BASE_DATA_DIR / case_id / "logs" / "phone_saved_flight.srt").exists()

    # Laptop UI polls /sync-status -> must see new sync_version and telemetry points!
    updated_sync = client.get(f"/api/cases/{case_id}/sync-status").json()
    assert updated_sync["sync_version"] > initial_ver
    assert updated_sync["evidence_count"] == 1
    assert updated_sync["telemetry_count"] >= 5
    assert updated_sync["wireless_count"] == 1
    assert updated_sync["evidence_counts"]["logs"] == 1
    assert updated_sync["evidence_counts"]["video_images"] == 0
    assert updated_sync["evidence_counts"]["gcs"] == 0


def test_evidence_api_category_filtering():
    """Verify GET /api/cases/{case_id}/evidence endpoint with category query filtering."""
    case_id = "FILTER-CASE-03"
    client.post("/api/cases", json={
        "case_id": case_id,
        "case_name": "Evidence Filter Test",
        "investigator_name": "Forensic Tech",
        "agency_name": "DFIR Lab"
    })

    # 1. Ingest Log
    with open("samples/dji_mavic3_telemetry.srt", "rb") as f:
        client.post(f"/api/cases/{case_id}/ingest", files={"file": ("flight.srt", f, "text/plain")})

    # 2. Ingest GCS Plan
    plan_bytes = b'{"fileType": "Plan", "version": 1, "mission": {"items": []}}'
    client.post(f"/api/cases/{case_id}/ingest", files={"file": ("mission.plan", plan_bytes, "application/json")})

    # 3. Fetch All
    all_res = client.get(f"/api/cases/{case_id}/evidence")
    assert all_res.status_code == 200
    all_data = all_res.json()
    assert all_data["total_count"] == 2
    assert all_data["counts"]["logs"] == 1
    assert all_data["counts"]["gcs"] == 1
    assert len(all_data["items"]) == 2

    # 4. Fetch Logs only
    logs_res = client.get(f"/api/cases/{case_id}/evidence?category=logs")
    assert logs_res.status_code == 200
    logs_data = logs_res.json()
    assert len(logs_data["items"]) == 1
    assert logs_data["items"][0]["file_name"] == "flight.srt"
    assert logs_data["items"][0]["evidence_category"] == "LOGS"

    # 5. Fetch GCS only
    gcs_res = client.get(f"/api/cases/{case_id}/evidence?category=gcs")
    assert gcs_res.status_code == 200
    gcs_data = gcs_res.json()
    assert len(gcs_data["items"]) == 1
    assert gcs_data["items"][0]["file_name"] == "mission.plan"
    assert gcs_data["items"][0]["evidence_category"] == "GCS"

    # 6. Fetch Video/Images only (should be empty for this case)
    media_res = client.get(f"/api/cases/{case_id}/evidence?category=video_images")
    assert media_res.status_code == 200
    assert len(media_res.json()["items"]) == 0


def test_court_reports_include_categorized_evidence():
    """Verify that both HTML and JSON court reports include categorized evidence data."""
    case_id = "REPORT-CASE-04"
    client.post("/api/cases", json={
        "case_id": case_id,
        "case_name": "Court Report Categorization Test",
        "investigator_name": "Capt. Forensics",
        "agency_name": "Aviation Police"
    })

    with open("samples/dji_mavic3_telemetry.srt", "rb") as f:
        client.post(f"/api/cases/{case_id}/ingest", files={"file": ("mavic3_log.srt", f, "text/plain")})

    # HTML Report
    html_res = client.get(f"/api/cases/{case_id}/report/html")
    assert html_res.status_code == 200
    html_text = html_res.text
    assert "Category" in html_text
    assert "📋 Logs" in html_text
    assert "Itemized Evidence &amp; Cryptographic Hashes" in html_text or "Itemized Evidence & Cryptographic Hashes" in html_text

    # JSON Report
    json_res = client.get(f"/api/cases/{case_id}/report/json")
    assert json_res.status_code == 200
    json_data = json_res.json()
    assert "evidence_counts" in json_data
    assert json_data["evidence_counts"]["logs"] == 1
    assert "evidence_by_category" in json_data
    assert len(json_data["evidence_by_category"]["logs"]) == 1
    assert json_data["evidence_by_category"]["logs"][0]["evidence_category"] == "LOGS"


def test_mobile_upload_portal_served():
    """Verify that the dedicated /upload and /mobile-upload portals are accessible."""
    res = client.get("/upload")
    assert res.status_code == 200
    assert "DFT Mobile Uplink" in res.text
    assert "mobileFileInput" in res.text
    assert "caseSelector" in res.text

    res2 = client.get("/mobile-upload")
    assert res2.status_code == 200
    assert "DFT Mobile Uplink" in res2.text

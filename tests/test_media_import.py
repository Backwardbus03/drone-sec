"""
Unit and Integration Tests for Media Evidence Ingestion, Telemetry Overlap Detection,
and Timeline Event Synchronization in Drone Forensic Toolkit (ISO/IEC 27037:2012).
"""

import io
import os
import tempfile
from pathlib import Path
from datetime import datetime, timezone
import pytest
import PIL.Image
import cv2
import numpy as np
from fastapi.testclient import TestClient

from dft.api.app import app
from dft.core.models import TelemetryPoint
from dft.acquisition.e01 import E01Writer
from dft.analysis.media_import import (
    detect_media_type,
    extract_frame_thumbnail,
    check_telemetry_overlap,
    process_media_file,
)

client = TestClient(app)


def test_e01_writer_and_verification():
    """Validates bit-exact E01 container packaging, section layout, and Adler-32 verification."""
    with tempfile.TemporaryDirectory() as tmpdir:
        src_file = Path(tmpdir) / "evidence_photo.jpg"
        test_payload = b"\xff\xd8\xff\xe0" + b"TEST_DRONE_IMAGE_DATA" * 500 + b"\xff\xd9"
        src_file.write_bytes(test_payload)

        e01_file = Path(tmpdir) / "evidence_photo.eo1"
        res = E01Writer.create_e01(
            source_file=src_file,
            output_file=e01_file,
            case_id="CASE-UNIT-01",
            evidence_id="EV-MED-001",
            examiner="Inspector Verma",
            description="Aerial surveillance photo"
        )
        assert res["status"] == "COMPLETED"
        assert e01_file.exists()
        assert res["e01_size_bytes"] > 0
        assert res["raw_size_bytes"] == len(test_payload)

        # Validate structure with verifier
        ver = E01Writer.verify_e01(e01_file)
        assert ver["valid"] is True
        assert ver["stored_md5"] == res["raw_md5"]
        assert "header" in ver["sections"]
        assert "volume" in ver["sections"]
        assert "sectors" in ver["sections"]
        assert "table" in ver["sections"]
        assert "hash" in ver["sections"]
        assert "done" in ver["sections"]


def test_detect_media_type():
    assert detect_media_type(Path("flight.mp4")) == "VIDEO"
    assert detect_media_type(Path("uav_clip.MOV")) == "VIDEO"
    assert detect_media_type(Path("stream.mkv")) == "VIDEO"
    assert detect_media_type(Path("aerial.jpg")) == "IMAGE"
    assert detect_media_type(Path("target.PNG")) == "IMAGE"
    assert detect_media_type(Path("raw.DNG")) == "IMAGE"
    assert detect_media_type(Path("sensor.tiff")) == "IMAGE"


def test_check_telemetry_overlap_logic():
    t0 = datetime(2026, 9, 13, 10, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 9, 13, 10, 5, 0, tzinfo=timezone.utc)

    telemetry = [
        TelemetryPoint(timestamp_utc=t0.isoformat(), latitude=19.100, longitude=72.900, altitude_m=30.0),
        TelemetryPoint(timestamp_utc=t1.isoformat(), latitude=19.105, longitude=72.905, altitude_m=60.0),
    ]

    # In-window photo
    t_inside = datetime(2026, 9, 13, 10, 2, 0, tzinfo=timezone.utc)
    res_in = check_telemetry_overlap(t_inside, None, telemetry, image_tolerance_sec=180.0)
    assert res_in["has_overlap"] is True
    assert res_in["matched_point"] is not None

    # Far-outside photo (2 hours later)
    t_far = datetime(2026, 9, 13, 12, 0, 0, tzinfo=timezone.utc)
    res_out = check_telemetry_overlap(t_far, None, telemetry, image_tolerance_sec=60.0)
    assert res_out["has_overlap"] is False
    assert res_out["matched_point"] is None

    # Video overlapping flight window
    res_vid = check_telemetry_overlap(t0, 120.0, telemetry)
    assert res_vid["has_overlap"] is True


def test_media_import_and_timeline_sync_api():
    import uuid
    case_id = f"CASE-MEDIA-{uuid.uuid4().hex[:8].upper()}"

    # 1. Initialize case
    create_res = client.post("/api/cases", json={
        "case_id": case_id,
        "case_name": "Media Ingestion Synchronization Suite",
        "investigator_name": "Senior Detective Singh",
        "agency_name": "State Drone Forensics Bureau",
        "description": "Validating multi-media import and timeline correlation"
    })
    assert create_res.status_code == 200

    # 2. Ingest telemetry flight log
    with open("samples/dji_mavic3_telemetry.srt", "rb") as f:
        ingest_res = client.post(
            f"/api/cases/{case_id}/ingest",
            files={"file": ("dji_mavic3_telemetry.srt", f, "text/plain")},
            data={"acquisition_type": "LOGICAL_EXTRACT", "actor": "Forensic Team"}
        )
    assert ingest_res.status_code == 200
    telemetry_pts = ingest_res.json()["telemetry_points_extracted"]
    assert telemetry_pts >= 5

    # 3. Create and Ingest Synchronized Drone Photo (EXIF date matches flight)
    img_bytes_io = io.BytesIO()
    im = PIL.Image.new("RGB", (320, 240), color=(50, 120, 200))
    exif = im.getexif()
    exif[306] = "2026:09:13 10:00:04"  # DateTime matching sample SRT flight time
    im.save(img_bytes_io, format="JPEG", exif=exif)
    img_bytes_io.seek(0)

    photo_res = client.post(
        f"/api/cases/{case_id}/ingest-media",
        files={"file": ("aerial_surveillance_snap.jpg", img_bytes_io, "image/jpeg")},
        data={"actor": "Forensic Specialist"}
    )
    assert photo_res.status_code == 200
    photo_data = photo_res.json()
    assert photo_data["status"] == "SUCCESS"
    assert photo_data["has_overlap"] is True
    assert photo_data["flight_event_created"] is True
    assert photo_data["flight_event"]["event_type"] == "MEDIA_CAPTURE"
    assert photo_data["media_item"]["thumbnail_base64"] is not None
    assert photo_data["has_e01"] is True
    assert photo_data["e01_path"] is not None
    assert Path(photo_data["e01_path"]).exists()
    assert Path(photo_data["e01_path"]).suffix.lower() == ".eo1"
    photo_item_id = photo_data["media_item"]["item_id"]

    # 4. Create and Ingest Synchronized Drone Video (MP4)
    with tempfile.TemporaryDirectory() as tmpdir:
        vid_file = Path(tmpdir) / "recon_clip.mp4"
        fourcc = cv2.VideoWriter_fourcc(*"mp4v")
        out = cv2.VideoWriter(str(vid_file), fourcc, 10.0, (160, 120))
        for i in range(25):
            frame = np.full((120, 160, 3), (180, 80, 40), dtype=np.uint8)
            out.write(frame)
        out.release()

        # Set MP4 creation tag to overlap with sample SRT flight
        flight_dt = datetime(2026, 9, 13, 10, 0, 6, tzinfo=timezone.utc)
        from mutagen.mp4 import MP4
        mp4 = MP4(str(vid_file))
        mp4["\xa9day"] = [flight_dt.strftime("%Y-%m-%d %H:%M:%S")]
        mp4.save()

        with open(vid_file, "rb") as f:
            vid_res = client.post(
                f"/api/cases/{case_id}/ingest-media",
                files={"file": ("recon_clip.mp4", f, "video/mp4")},
                data={"actor": "Forensic Specialist", "capture_timestamp": flight_dt.isoformat()}
            )
        assert vid_res.status_code == 200
        vid_data = vid_res.json()
        assert vid_data["status"] == "SUCCESS"
        assert vid_data["has_overlap"] is True
        assert vid_data["has_e01"] is True
        assert vid_data["e01_path"] is not None
        assert Path(vid_data["e01_path"]).exists()
        assert vid_data["flight_event_created"] is True
        assert vid_data["flight_event"]["event_type"] == "MEDIA_CAPTURE"
        assert vid_data["media_item"]["media_type"] == "VIDEO"
        assert vid_data["media_item"]["duration_sec"] is not None
        assert vid_data["media_item"]["thumbnail_base64"] is not None
        vid_item_id = vid_data["media_item"]["item_id"]

    # 5. Create and Ingest Unrelated Non-overlapping Image (2 weeks earlier)
    unrelated_io = io.BytesIO()
    im_old = PIL.Image.new("RGB", (100, 100), color=(10, 10, 10))
    exif_old = im_old.getexif()
    exif_old[306] = "2026:08:01 12:00:00"
    im_old.save(unrelated_io, format="JPEG", exif=exif_old)
    unrelated_io.seek(0)

    unrelated_res = client.post(
        f"/api/cases/{case_id}/ingest-media",
        files={"file": ("unrelated_photo.jpg", unrelated_io, "image/jpeg")}
    )
    assert unrelated_res.status_code == 200
    unrelated_data = unrelated_res.json()
    assert unrelated_data["has_overlap"] is False
    assert unrelated_data["has_e01"] is False
    assert unrelated_data["e01_path"] is None
    assert unrelated_data["flight_event_created"] is False

    # 6. Verify master timeline contains exactly the 2 synchronized MEDIA_CAPTURE events
    tl_res = client.get(f"/api/cases/{case_id}/timeline")
    assert tl_res.status_code == 200
    timeline = tl_res.json()
    media_events = [it for it in timeline if it.get("event_type") == "MEDIA_CAPTURE"]
    assert len(media_events) == 2
    for me in media_events:
        assert me["latitude"] is not None
        assert me["longitude"] is not None
        assert me["altitude_m"] is not None

    # 7. Check media catalog endpoint
    media_res = client.get(f"/api/cases/{case_id}/media")
    assert media_res.status_code == 200
    all_media = media_res.json()
    assert len(all_media) == 3

    # 8. Test thumbnail endpoint
    thumb_photo = client.get(f"/api/cases/{case_id}/media/{photo_item_id}/thumbnail")
    assert thumb_photo.status_code == 200
    assert thumb_photo.headers["content-type"] == "image/jpeg"
    assert len(thumb_photo.content) > 100

    thumb_vid = client.get(f"/api/cases/{case_id}/media/{vid_item_id}/thumbnail")
    assert thumb_vid.status_code == 200
    assert thumb_vid.headers["content-type"] == "image/jpeg"
    assert len(thumb_vid.content) > 100

    # 9. Verify Chain of Custody logged entries
    coc_res = client.get(f"/api/cases/{case_id}/audit-trail")
    assert coc_res.status_code == 200
    coc_entries = coc_res.json()
    media_coc = [e for e in coc_entries if e["action"] == "MEDIA_EVIDENCE_INGESTED"]
    assert len(media_coc) == 3
    e01_coc = [e for e in coc_entries if e["action"] == "FORENSIC_EO1_IMAGE_CREATED"]
    assert len(e01_coc) >= 1

    # 10. Test E01 download endpoint
    e01_download = client.get(f"/api/cases/{case_id}/media/{photo_item_id}/e01")
    assert e01_download.status_code == 200
    assert e01_download.content[:8] == b"EVF\t\r\n\xff\x00"

    # 11. Verify HTML report includes Aerial Visual Evidence section & embedded images
    html_res = client.get(f"/api/cases/{case_id}/report/html")
    assert html_res.status_code == 200
    assert "Aerial Visual Evidence & Synchronized Media Captures" in html_res.text
    assert "aerial_surveillance_snap.jpg" in html_res.text
    assert ".eo1" in html_res.text
    assert "data:image/jpeg;base64," in html_res.text
    assert "✓ SYNCHRONIZED" in html_res.text

    # 12. Verify JSON report includes media_items
    json_res = client.get(f"/api/cases/{case_id}/report/json")
    assert json_res.status_code == 200
    j_data = json_res.json()
    assert "media_items" in j_data
    assert len(j_data["media_items"]) == 3

    # 13. Verify DFXML report includes visual_media objects
    dfxml_res = client.get(f"/api/cases/{case_id}/report/dfxml")
    assert dfxml_res.status_code == 200
    assert 'type="visual_media"' in dfxml_res.text

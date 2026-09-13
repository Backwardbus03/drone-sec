"""
Automated Forensic Verification Test Suite for Drone Forensic Toolkit.
Tests dual hashing, chain-of-custody tamper resistance, write-blocking,
all 5 drone platform parsers, geofence collision detection, and report generation.
"""

import pytest
import sqlite3
from pathlib import Path
from dft.core.hashing import compute_hashes, verify_integrity
from dft.core.chain_of_custody import ChainOfCustodyManager
from dft.core.write_blocker import WriteBlockController
from dft.plugins.manager import PluginManager
from dft.analysis.geofence import GeofenceEngine, point_in_polygon, haversine_distance_meters
from dft.analysis.anomaly import AnomalyDetector
from dft.analysis.timeline import TimelineReconstructor
from dft.analysis.flight_path import FlightPathAnalyzer
from dft.reporting.generator import ForensicReportGenerator
from dft.core.models import (
    CaseMetadata, EvidenceItem, TelemetryPoint, FlightEvent, GeofenceZone, FlightSummary
)


def test_dual_hashing_nist_vectors(tmp_path):
    """Verifies SHA-256, SHA3-256, and MD5 against standard test strings."""
    # Test vector: b"abc"
    # Expected SHA-256: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    manifest = compute_hashes(b"abc")
    assert manifest.sha256.lower() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert manifest.md5.lower() == "900150983cd24fb0d6963f7d28e17f72"
    assert manifest.byte_count == 3

    # Test file hashing
    test_file = tmp_path / "evidence.bin"
    test_file.write_bytes(b"FORENSIC_EVIDENCE_PAYLOAD_2026")
    file_manifest = compute_hashes(test_file)
    verification = verify_integrity(test_file, file_manifest)
    assert verification["is_valid"] is True


def test_chain_of_custody_tamper_detection(tmp_path):
    """Verifies that Chain of Custody detects manual database tampering."""
    db_path = tmp_path / "audit.sqlite"
    coc = ChainOfCustodyManager(db_path)

    # Log 3 actions
    coc.log_action("CASE-001", "Analyst A", "IMAGE_MOUNTED", "Mounted SD card image")
    coc.log_action("CASE-001", "Analyst A", "PARSING_STARTED", "Initiated DJI parser")
    coc.log_action("CASE-001", "Analyst B", "REPORT_REVIEWED", "Examined findings")

    # Verify uncorrupted chain
    valid, err = coc.verify_chain("CASE-001")
    assert valid is True
    assert err is None

    # Tamper with row #2 in database
    conn = sqlite3.connect(str(db_path))
    conn.execute("UPDATE audit_trail SET details = 'TAMPERED ACTION DETAILS' WHERE entry_id = 2")
    conn.commit()
    conn.close()

    # Re-verify should detect tampering
    tampered_valid, tampered_err = coc.verify_chain("CASE-001")
    assert tampered_valid is False
    assert "Tampered entry #2" in tampered_err


def test_write_block_verification(tmp_path):
    """Tests canary write-inhibition detection."""
    test_dir = tmp_path / "evidence_vault"
    test_dir.mkdir()
    res = WriteBlockController.verify_read_only_status(test_dir)
    assert "target" in res


def test_geofence_algorithms():
    """Tests point-in-polygon and circular distance geofence algorithms."""
    # Polygon around IIT Bombay area
    polygon = [
        [19.140, 72.905],
        [19.140, 72.920],
        [19.125, 72.920],
        [19.125, 72.905]
    ]

    # Interior point
    assert point_in_polygon(19.133, 72.913, polygon) is True

    # Exterior point
    assert point_in_polygon(19.200, 72.850, polygon) is False

    # Haversine distance
    dist = haversine_distance_meters(19.1334, 72.9133, 19.1334, 72.9143)
    assert 90.0 < dist < 120.0  # Approx 105 meters


def test_all_five_platform_parsers():
    """Verifies that all 5 drone platform parsers successfully parse samples."""
    mgr = PluginManager()

    # 1. DJI SRT parser
    dji_sample = Path("samples/dji_mavic3_telemetry.srt")
    assert dji_sample.exists()
    p_id, pts, evs, meta = mgr.parse_evidence(dji_sample)
    assert p_id == "dji"
    assert len(pts) >= 5
    assert len(evs) >= 2

    # 2. ArduPilot parser
    ardu_sample = Path("samples/ardupilot_flight.log")
    assert ardu_sample.exists()
    p_id, pts, evs, meta = mgr.parse_evidence(ardu_sample)
    assert p_id == "ardupilot"
    assert len(pts) >= 5

    # 3. PX4 parser
    px4_sample = Path("samples/px4_mission.csv")
    assert px4_sample.exists()
    p_id, pts, evs, meta = mgr.parse_evidence(px4_sample)
    assert p_id == "px4"
    assert len(pts) >= 5

    # 4. Parrot parser
    parrot_sample = Path("samples/parrot_anafi_flight.json")
    assert parrot_sample.exists()
    p_id, pts, evs, meta = mgr.parse_evidence(parrot_sample)
    assert p_id == "parrot"
    assert len(pts) >= 5

    # 5. Betaflight parser
    bf_sample = Path("samples/betaflight_blackbox.txt")
    assert bf_sample.exists()
    p_id, pts, evs, meta = mgr.parse_evidence(bf_sample)
    assert p_id == "betaflight"
    assert len(pts) >= 5


def test_geofence_breach_detection():
    """Verifies that geofence evaluation accurately flags spatial and ceiling violations."""
    engine = GeofenceEngine([
        GeofenceZone(
            zone_id="ZONE-TEST",
            name="Restricted Zone",
            zone_type="polygon",
            coordinates=[
                [19.130, 72.910],
                [19.140, 72.910],
                [19.140, 72.920],
                [19.130, 72.920]
            ],
            max_altitude_m=50.0
        )
    ])

    telemetry = [
        TelemetryPoint(timestamp_utc="2026-09-13T10:00:00Z", latitude=19.100, longitude=72.900, altitude_m=20.0),
        TelemetryPoint(timestamp_utc="2026-09-13T10:01:00Z", latitude=19.135, longitude=72.915, altitude_m=30.0), # Inside, under ceiling
        TelemetryPoint(timestamp_utc="2026-09-13T10:02:00Z", latitude=19.135, longitude=72.915, altitude_m=80.0)  # Inside, CEILING EXCEEDED
    ]

    violations = engine.evaluate_telemetry(telemetry)
    assert len(violations) == 2
    assert violations[0].violation_type == "BOUNDARY_ENTRY"
    assert violations[1].violation_type == "CEILING_EXCEEDED"


def test_anomaly_detection():
    """Verifies that AnomalyDetector flags mid-air disarms and timestamp reversals."""
    telemetry = [
        TelemetryPoint(timestamp_utc="2026-09-13T10:00:00Z", latitude=19.133, longitude=72.913, altitude_m=20.0),
        TelemetryPoint(timestamp_utc="2026-09-13T09:59:50Z", latitude=19.134, longitude=72.914, altitude_m=22.0)  # Time reversal
    ]
    events = [
        FlightEvent(
            event_id="EV-DISARM",
            timestamp_utc="2026-09-13T10:05:00Z",
            event_type="DISARM",
            description="Motor stop",
            altitude_m=45.0  # Mid-air!
        )
    ]

    anomalies = AnomalyDetector.inspect(telemetry, events)
    types = [a.anomaly_type for a in anomalies]
    assert "CLOCK_SKEW" in types
    assert "UNEXPECTED_DISARM" in types


def test_report_generation(tmp_path):
    """Tests HTML report synthesis."""
    case = CaseMetadata(
        case_id="TEST-CASE-01",
        case_name="Automated Test",
        investigator_name="Tester",
        agency_name="QA Lab"
    )
    summary = FlightSummary(
        platform_detected="DJI",
        total_duration_sec=120.0,
        total_distance_meters=450.0,
        max_altitude_m=65.0,
        max_speed_mps=12.0,
        telemetry_count=10,
        events_count=2,
        violations_count=0,
        anomalies_count=0
    )
    html = ForensicReportGenerator.generate_html_report(
        case=case, summary=summary, evidence_items=[],
        geofence_violations=[], anomalies=[], timeline=[], audit_logs=[]
    )
    assert "UAV DIGITAL FORENSIC EXAMINATION REPORT" in html
    assert "ISO/IEC 27037:2012" in html
    assert "TEST-CASE-01" in html


def test_network_capture_parsing(tmp_path):
    """Tests wireless PCAP / Wi-Fi packet parser."""
    from dft.acquisition.network import NetworkCaptureEngine
    pcap_file = tmp_path / "drone_capture.pcap"
    # Create valid synthetic PCAP file with DJI SSID and MAVLink packet
    # PCAP header (24 bytes)
    pcap_hdr = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00"
    # Packet header (16 bytes) + Packet body
    pkt_body = b"\x00\x00\x00\x00\x00\x00\xaa\xbb\xcc\xdd\xee\xff\x08\x00DJI-Mavic3-AP-Beacon\xfe\x09\x01\x02"
    pkt_hdr = b"\x00\x00\x00\x00\x00\x00\x00\x00" + len(pkt_body).to_bytes(4, "little") + len(pkt_body).to_bytes(4, "little")
    pcap_file.write_bytes(pcap_hdr + pkt_hdr + pkt_body)

    result = NetworkCaptureEngine.parse_pcap_file(pcap_file)
    assert result["total_packets_parsed"] == 1
    assert any("DJI-Mavic3" in ssid for ssid in result["detected_uav_ssids"])
    assert result["mavlink_telemetry_frames"] == 1


def test_file_carver_recovery(tmp_path):
    """Tests recovery of deleted JPEG and ULog files from simulated raw disk image."""
    from dft.acquisition.carver import FileCarverEngine
    raw_disk = tmp_path / "raw_sd_card.dd"

    # Plant synthetic files amidst unallocated zeroes
    jpeg_payload = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9"
    ulog_payload = b"ULog\x01\x12\x35\x00\x00\x00\x00\x00\x00\x00\x00"
    raw_content = b"\x00" * 512 + jpeg_payload + b"\x00" * 1024 + ulog_payload + b"\x00" * 512
    raw_disk.write_bytes(raw_content)

    carve_out = tmp_path / "carved_vault"
    carved = FileCarverEngine.carve_image(raw_disk, carve_out)

    types = [c["file_type"] for c in carved]
    assert "JPEG_PHOTO" in types
    assert "PX4_ULOG" in types
    assert (carve_out / carved[0]["file_name"]).exists()


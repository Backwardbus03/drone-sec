"""
Automated Test Suite for Cross-Platform Mobile Companion Applications
and Forensic Wireless Data Acquisition in Drone Forensic Toolkit (DFT).

Validates mobile companion app decoders across all 5+ drone platforms
(DJI Fly/GO/Litchi, ArduPilot/PX4 QGC, Parrot FreeFlight, Betaflight SpeedyBee, Autel Explorer),
smartphone GPS operator geolocation recovery, pilot identity extraction,
wireless data acquisition engine, API endpoints, and forensic reporting.
"""

import csv
import json
import sqlite3
import tempfile
import zipfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from dft.core.models import (
    CaseMetadata, EvidenceItem, TelemetryPoint, OperatorLocation, FlightSummary,
    MobileAppArtifact, MobileCompanionAnalysisResult, WirelessTransferSession
)
from dft.analysis.mobile import MobileCompanionAnalyzer, MOBILE_APP_CATALOG
from dft.acquisition.mobile import MobileAcquisitionEngine
from dft.acquisition.wireless import WirelessAcquisitionEngine
from dft.reporting.generator import ForensicReportGenerator
from dft.analysis.flight_path import FlightPathAnalyzer
from dft.api.app import app


client = TestClient(app)


# -----------------------------------------------------------------------------
# 1. CATALOG & PLATFORM IDENTIFICATION TESTS
# -----------------------------------------------------------------------------

def test_mobile_catalog_completeness():
    catalog = MobileCompanionAnalyzer.get_supported_catalog()
    assert len(catalog) >= 6

    platforms = set(app["platform"] for app in catalog)
    assert "DJI" in platforms
    assert "ArduPilot / PX4" in platforms
    assert "Parrot" in platforms
    assert "Betaflight / iNav" in platforms
    assert "Autel Robotics" in platforms

    app_names = [a["app_name"] for a in catalog]
    assert "DJI Fly" in app_names
    assert "Litchi for DJI Drones" in app_names
    assert "QGroundControl Mobile" in app_names
    assert "Parrot FreeFlight 6 / Pro / 7" in app_names
    assert "SpeedyBee Mobile App" in app_names
    assert "Autel Explorer / Sky" in app_names


def test_identify_mobile_platform_from_paths_and_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)

        # Litchi CSV
        f_litchi = td / "2026-09-14 10-00-00.csv"
        f_litchi.write_text("datetime(utc),latitude,longitude,altitude(m),phone_latitude,phone_longitude\n", encoding="utf-8")
        app_name, pkg, plat = MobileCompanionAnalyzer.identify_mobile_platform(f_litchi)
        assert app_name == "Litchi for DJI Drones"
        assert plat == "DJI"

        # SpeedyBee CLI diff
        f_sb = td / "speedybee_cli_backup.diff"
        f_sb.write_text("# Betaflight / STM32F405 4.4.2\nset callsign = SPECTRE_FPV\nset failsafe_procedure = GPS-RESCUE\n", encoding="utf-8")
        app_name, pkg, plat = MobileCompanionAnalyzer.identify_mobile_platform(f_sb)
        assert app_name == "SpeedyBee Mobile App"
        assert plat == "Betaflight / iNav"

        # Parrot FreeFlight JSON
        f_parrot = td / "parrot_flight_data.json"
        f_parrot.write_text(json.dumps({"app": "FreeFlight 6", "serial_number": "PI040384AA8K123456", "details": []}), encoding="utf-8")
        app_name, pkg, plat = MobileCompanionAnalyzer.identify_mobile_platform(f_parrot)
        assert app_name == "Parrot FreeFlight 6"
        assert plat == "Parrot"

        # QGroundControl
        f_qgc = td / "org.mavlink.qgroundcontrol" / "Missions" / "survey.plan"
        f_qgc.parent.mkdir(parents=True, exist_ok=True)
        f_qgc.write_text("{}", encoding="utf-8")
        app_name, pkg, plat = MobileCompanionAnalyzer.identify_mobile_platform(f_qgc)
        assert app_name == "QGroundControl Mobile"
        assert plat == "ArduPilot / PX4"


# -----------------------------------------------------------------------------
# 2. PLATFORM SPECIFIC DECODERS
# -----------------------------------------------------------------------------

def test_litchi_csv_and_operator_phone_gps():
    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)
        csv_file = td / "Litchi_flight_log.csv"

        rows = [
            "datetime(utc),latitude,longitude,altitude(m),speed(m/s),pitch,roll,yaw,phone_latitude,phone_longitude,home_latitude,home_longitude",
            "2026-09-14T10:00:00Z,19.133400,72.913300,10.5,2.4,-1.2,0.8,45.0,19.132500,72.912800,19.132600,72.912900",
            "2026-09-14T10:00:01Z,19.133450,72.913350,15.2,4.8,-2.1,1.0,46.2,19.132500,72.912800,19.132600,72.912900",
            "2026-09-14T10:00:02Z,19.133500,72.913400,20.0,6.1,-2.5,1.2,47.5,19.132500,72.912800,19.132600,72.912900"
        ]
        csv_file.write_text("\n".join(rows), encoding="utf-8")

        pts, op_loc = MobileCompanionAnalyzer._parse_litchi_csv(csv_file)
        assert len(pts) == 3
        assert pts[0].latitude == 19.133400
        assert pts[0].altitude_m == 10.5
        assert pts[0].source_channel == "LITCHI_MOBILE_LOG"

        assert op_loc is not None
        assert op_loc.source == "Litchi Mobile Phone GPS"
        assert round(op_loc.latitude, 6) == 19.132500
        assert round(op_loc.longitude, 6) == 72.912800


def test_dji_sqlite_database_parsing():
    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)
        db_file = td / "flight_record.db"

        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE UserInfo (user_id TEXT, user_name TEXT, email TEXT, phone TEXT);")
        cursor.execute("INSERT INTO UserInfo VALUES ('UID-99482', 'Pilot_Ghost', 'operator@surveillance.net', '+91-9876543210');")
        cursor.execute("CREATE TABLE FlightRecord (id INTEGER PRIMARY KEY, drone_sn TEXT, flight_time REAL);")
        cursor.execute("INSERT INTO FlightRecord (drone_sn, flight_time) VALUES ('3N3DJI99824X', 482.5);")
        cursor.execute("INSERT INTO FlightRecord (drone_sn, flight_time) VALUES ('3N3DJI99824X', 312.0);")
        conn.commit()
        conn.close()

        acc, hw, count = MobileCompanionAnalyzer._parse_dji_sqlite(db_file)
        assert acc.get("email") == "operator@surveillance.net"
        assert acc.get("pilot_name") == "Pilot_Ghost"
        assert acc.get("user_id") == "UID-99482"
        assert hw.get("aircraft_sn") == "3N3DJI99824X"
        assert count == 2


def test_parrot_mobile_log_parsing():
    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)
        json_file = td / "parrot_flight_data.json"

        data = {
            "serial_number": "PI040384AA8K123456",
            "controller_latitude": 19.132950,
            "controller_longitude": 72.912550,
            "details": [
                {"timestamp": "2026-09-14T10:05:00Z", "gps_latitude": 19.133600, "gps_longitude": 72.913500, "altitude": 32.0},
                {"timestamp": "2026-09-14T10:05:01Z", "gps_latitude": 19.133650, "gps_longitude": 72.913550, "altitude": 34.5}
            ]
        }
        json_file.write_text(json.dumps(data), encoding="utf-8")

        pts, op_loc, sn = MobileCompanionAnalyzer._parse_parrot_mobile_log(json_file)
        assert len(pts) == 2
        assert sn == "PI040384AA8K123456"
        assert op_loc is not None
        assert round(op_loc.latitude, 6) == 19.132950
        assert round(op_loc.longitude, 6) == 72.912550
        assert "Parrot" in op_loc.source


def test_speedybee_cli_parsing():
    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)
        diff_file = td / "speedybee_dump.diff"

        lines = [
            "# Betaflight / STM32F405 (S405) 4.4.2 May 31 2023",
            "name PHANTOM_PILOT",
            "set callsign = PHANTOM_PILOT",
            "set failsafe_procedure = GPS-RESCUE",
            "set motor_pwm_protocol = DSHOT600",
            "set gps_rescue_min_sats = 6"
        ]
        diff_file.write_text("\n".join(lines), encoding="utf-8")

        conf = MobileCompanionAnalyzer._parse_speedybee_cli(diff_file)
        assert conf.get("callsign") == "PHANTOM_PILOT"
        assert conf.get("failsafe_procedure") == "GPS-RESCUE"
        assert conf.get("motor_protocol") == "DSHOT600"
        assert conf.get("gps_rescue_min_sats") == "6"


def test_autel_mobile_log_parsing():
    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)
        csv_file = td / "Autel_FlightRecord.csv"

        rows = [
            "datetime,latitude,longitude,altitude,home_lat,home_lon,sn",
            "2026-09-14T10:10:00Z,19.133800,72.913700,50.0,19.132800,72.912700,AUTEL-EVO2-7712",
            "2026-09-14T10:10:01Z,19.133850,72.913750,52.5,19.132800,72.912700,AUTEL-EVO2-7712"
        ]
        csv_file.write_text("\n".join(rows), encoding="utf-8")

        pts, op_loc, sn = MobileCompanionAnalyzer._parse_autel_mobile_log(csv_file)
        assert len(pts) == 2
        assert sn == "AUTEL-EVO2-7712"
        assert op_loc is not None
        assert round(op_loc.latitude, 6) == 19.132800


# -----------------------------------------------------------------------------
# 3. MOBILE ARCHIVE EXTRACTION & ACQUISITION TESTS
# -----------------------------------------------------------------------------

def test_mobile_acquisition_archive_extraction():
    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)
        archive_path = td / "phone_backup.zip"
        vault_dest = td / "vault_dest"

        # Create zip with simulated mobile files
        with zipfile.ZipFile(archive_path, "w") as z:
            z.writestr("sdcard/Litchi/flightlogs/2026-09-14.csv", "datetime(utc),latitude,longitude,phone_latitude,phone_longitude\n2026-09-14T10:00:00Z,19.133,72.913,19.132,72.912\n")
            z.writestr("sdcard/SpeedyBee/CLI/config.diff", "set callsign = HAWK\n")

        manifest = MobileAcquisitionEngine.extract_mobile_archive(archive_path, vault_dest)
        assert manifest["files_extracted_count"] == 2
        assert (vault_dest / "sdcard/Litchi/flightlogs/2026-09-14.csv").exists()
        assert (vault_dest / "sdcard/SpeedyBee/CLI/config.diff").exists()

        # Run analysis on the extracted directory
        result = MobileCompanionAnalyzer.analyze_mobile_evidence(vault_dest)
        assert len(result.artifacts) >= 2
        app_names = [a.app_name for a in result.artifacts]
        assert "Litchi for DJI Drones" in app_names
        assert "SpeedyBee Mobile App" in app_names


def test_generate_adb_pull_plan():
    plan = MobileAcquisitionEngine.generate_adb_pull_plan(["dji.go.v5", "com.runcam.speedybee"])
    assert plan["total_targets"] > 0
    commands = [c["command"] for c in plan["adb_commands"]]
    assert any("dji.go.v5" in cmd for cmd in commands)
    assert any("SpeedyBee" in cmd for cmd in commands)


# -----------------------------------------------------------------------------
# 4. WIRELESS ACQUISITION ENGINE TESTS
# -----------------------------------------------------------------------------

def test_wireless_wifi_ap_acquisition():
    with tempfile.TemporaryDirectory() as tmpdir:
        dest = Path(tmpdir) / "wireless_wifi"
        session = WirelessAcquisitionEngine.acquire_wifi_ap(
            target_ip="192.168.42.1",
            port=21,
            platform_hint="Parrot",
            destination_dir=dest,
            simulate_mock_if_offline=True
        )
        assert session.status == "COMPLETED"
        assert session.protocol == "WIFI_FTP"
        assert session.drone_platform == "Parrot"
        assert len(session.files_acquired) == 1
        assert session.hash_manifest is not None
        assert len(session.hash_manifest.sha256) == 64


def test_wireless_mavlink_capture():
    with tempfile.TemporaryDirectory() as tmpdir:
        dest = Path(tmpdir) / "wireless_mavlink"
        session = WirelessAcquisitionEngine.capture_mavlink_stream(
            udp_port=14552,  # custom port
            duration_sec=0.2,
            destination_dir=dest,
            simulate_mock_if_no_packets=True
        )
        assert session.status == "COMPLETED"
        assert session.protocol == "MAVLINK_UDP"
        assert session.drone_platform == "ArduPilot / PX4"
        assert len(session.files_acquired) == 1
        assert session.hash_manifest is not None
        assert session.bytes_transferred > 0


def test_wireless_direct_mobile_upload():
    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)
        up_file = td / "mobile_flight.csv"
        up_file.write_text("time,lat,lon\n", encoding="utf-8")

        session = WirelessAcquisitionEngine.process_direct_mobile_upload(
            uploaded_files=[up_file],
            client_ip="192.168.1.155",
            user_agent="Mobile Safari iOS 17"
        )
        assert session.protocol == "LOCAL_HTTP_PORTAL"
        assert session.status == "COMPLETED"
        assert session.source_ip == "192.168.1.155"
        assert session.files_acquired == ["mobile_flight.csv"]


# -----------------------------------------------------------------------------
# 5. REST API ENDPOINTS TESTS
# -----------------------------------------------------------------------------

def test_api_mobile_and_wireless_endpoints():
    case_id = "CASE-TEST-MOBILE-01"
    # Create Case
    res = client.post("/api/cases", json={
        "case_id": case_id,
        "case_name": "Mobile Evidence Investigation",
        "investigator_name": "Agent Vance",
        "agency_name": "Cyber Cell",
        "description": "Phone & wireless companion test"
    })
    assert res.status_code == 200

    # 1. Get supported mobile catalog
    res_cat = client.get("/api/mobile/supported-apps")
    assert res_cat.status_code == 200
    cat = res_cat.json()
    assert len(cat) >= 6

    # 2. Get supported wireless modes
    res_wire = client.get("/api/wireless/supported-modes")
    assert res_wire.status_code == 200
    assert len(res_wire.json()) >= 3

    # 3. Ingest mobile evidence file
    csv_content = (
        "datetime(utc),latitude,longitude,altitude(m),phone_latitude,phone_longitude\n"
        "2026-09-14T10:00:00Z,19.1334,72.9133,50,19.1325,72.9128\n"
        "2026-09-14T10:00:01Z,19.1335,72.9134,52,19.1325,72.9128\n"
    ).encode("utf-8")

    ingest_res = client.post(
        f"/api/cases/{case_id}/ingest",
        files={"file": ("litchi_phone_log.csv", csv_content, "text/csv")},
        data={"acquisition_type": "LOGICAL_EXTRACT", "actor": "Agent Vance"}
    )
    assert ingest_res.status_code == 200
    ing_data = ingest_res.json()
    assert "Litchi for DJI Drones" in ing_data.get("mobile_apps_detected", [])

    # 4. Fetch mobile analysis for case
    res_mob = client.get(f"/api/cases/{case_id}/mobile")
    assert res_mob.status_code == 200
    mob_data = res_mob.json()
    assert "Litchi for DJI Drones" in mob_data["apps_detected"]
    assert len(mob_data["operator_locations"]) >= 1
    assert round(mob_data["operator_locations"][0]["latitude"], 4) == 19.1325

    # 5. Execute wireless acquisition endpoint
    acq_res = client.post(f"/api/cases/{case_id}/wireless/acquire", json={
        "mode": "WIFI_FTP",
        "target_ip": "192.168.42.1",
        "port": 21,
        "platform_hint": "Parrot",
        "duration_sec": 1.0,
        "actor": "Agent Vance"
    })
    assert acq_res.status_code == 200
    sess = acq_res.json()
    assert sess["protocol"] == "WIFI_FTP"
    assert sess["status"] == "COMPLETED"

    # 6. Fetch wireless sessions
    wire_res = client.get(f"/api/cases/{case_id}/wireless")
    assert wire_res.status_code == 200
    sessions = wire_res.json()
    assert len(sessions) >= 1

    # 7. Check summary includes mobile companion apps
    sum_res = client.get(f"/api/cases/{case_id}/summary")
    assert sum_res.status_code == 200
    sum_data = sum_res.json()
    assert "Litchi for DJI Drones" in sum_data.get("mobile_companion_apps", [])
    assert sum_data.get("wireless_sessions_count") >= 1


# -----------------------------------------------------------------------------
# 6. COURT REPORTING INTEGRATION TEST
# -----------------------------------------------------------------------------

def test_court_reporting_with_mobile_and_wireless():
    case = CaseMetadata(
        case_id="CASE-REP-01",
        case_name="Report Test",
        investigator_name="Examiner Cross",
        agency_name="Forensic Lab"
    )
    summary = FlightSummary(
        platform_detected="DJI",
        total_duration_sec=300.0,
        total_distance_meters=1500.0,
        max_altitude_m=80.0,
        max_speed_mps=14.0,
        telemetry_count=50,
        events_count=3,
        violations_count=0,
        anomalies_count=0,
        mobile_companion_apps=["Litchi for DJI Drones"],
        wireless_sessions_count=1
    )

    art = MobileAppArtifact(
        app_id="MOB-01",
        app_name="Litchi for DJI Drones",
        package_id="com.flylitchi.litchi",
        target_platform="DJI",
        pilot_account={"email": "pilot@flight.com", "pilot_name": "SkyWalker"},
        paired_hardware={"aircraft_sn": "3N3DJI12345"},
        operator_locations=[OperatorLocation(source="Phone GPS", latitude=19.1325, longitude=72.9128)],
        flight_logs=["2026-09-14.csv"]
    )
    mob_res = MobileCompanionAnalysisResult(
        apps_detected=["Litchi for DJI Drones"],
        platforms_involved=["DJI"],
        artifacts=[art],
        total_flight_records=1,
        operator_locations=art.operator_locations
    )
    ws = WirelessTransferSession(
        session_id="WIFI-TEST01",
        protocol="WIFI_FTP",
        source_ip="192.168.42.1",
        target_device="Parrot Drone AP",
        bytes_transferred=512,
        files_acquired=["flight_record.json"]
    )

    # HTML Report
    html = ForensicReportGenerator.generate_html_report(
        case=case,
        summary=summary,
        evidence_items=[],
        geofence_violations=[],
        anomalies=[],
        timeline=[],
        audit_logs=[],
        mobile_analysis=mob_res,
        wireless_sessions=[ws]
    )
    assert "Mobile Companion Applications & Wireless Acquisition Forensics" in html
    assert "Litchi for DJI Drones" in html
    assert "pilot@flight.com" in html
    assert "3N3DJI12345" in html
    assert "WIFI-TEST01" in html

    # JSON Report
    json_str = ForensicReportGenerator.generate_json_export(
        case=case,
        summary=summary,
        evidence_items=[],
        geofence_violations=[],
        anomalies=[],
        timeline=[],
        audit_logs=[],
        mobile_analysis=mob_res,
        wireless_sessions=[ws]
    )
    parsed = json.loads(json_str)
    assert "mobile_companion_analysis" in parsed
    assert "wireless_sessions" in parsed
    assert parsed["mobile_companion_analysis"]["apps_detected"] == ["Litchi for DJI Drones"]
    assert parsed["wireless_sessions"][0]["session_id"] == "WIFI-TEST01"

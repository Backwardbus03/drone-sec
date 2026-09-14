"""
Comprehensive Automated Test Suite for Cross-Platform Ground Control Station (GCS)
and Operator Forensics in Drone Forensic Toolkit (DFT).

Validates GCS artifact decoding, operator geolocation recovery, autonomous mission
plan parsing across all 5 FC types (ArduPilot, PX4, DJI, Betaflight/iNav, Parrot),
trajectory adherence comparison, API endpoints, and reporting.
"""

import json
import struct
import tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from dft.core.models import (
    PlannedWaypoint, GCSMissionPlan, OperatorLocation, TelemetryPoint, CaseMetadata, EvidenceItem
)
from dft.analysis.gcs import GCSAnalyzer
from dft.plugins.manager import PluginManager
from dft.api.app import app
from dft.reporting.generator import ForensicReportGenerator


client = TestClient(app)


# -----------------------------------------------------------------------------
# 1. Format Identification Tests
# -----------------------------------------------------------------------------

def test_identify_gcs_format():
    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)

        # MAVLink .tlog
        f_tlog = td / "flight.tlog"
        f_tlog.write_bytes(b"\x00" * 32)
        gcs, fc = GCSAnalyzer.identify_gcs_format(f_tlog)
        assert gcs is not None and ("Mission Planner" in gcs or "QGroundControl" in gcs)
        assert fc is not None and ("ArduPilot" in fc or "PX4" in fc)

        # QGC WPL .waypoints
        f_wpl = td / "mission.waypoints"
        f_wpl.write_text("QGC WPL 110\n0 1 0 16 0 0 0 0 19.133 72.913 50 1\n", encoding="utf-8")
        gcs, fc = GCSAnalyzer.identify_gcs_format(f_wpl)
        assert gcs is not None and ("QGroundControl" in gcs or "Mission Planner" in gcs)

        # QGC .plan
        f_plan = td / "auto_survey.plan"
        f_plan.write_text(json.dumps({"groundStation": "QGroundControl", "mission": {"items": []}}), encoding="utf-8")
        gcs, fc = GCSAnalyzer.identify_gcs_format(f_plan)
        assert gcs == "QGroundControl"
        assert fc is not None and ("PX4" in fc or "ArduPilot" in fc)

        # DJI WPML .kml
        f_kml = td / "dji_mission.kml"
        f_kml.write_text('<kml xmlns:wpml="http://www.dji.com/wpmz/1.0.2"><Folder></Folder></kml>', encoding="utf-8")
        gcs, fc = GCSAnalyzer.identify_gcs_format(f_kml)
        assert gcs is not None and "DJI Pilot 2" in gcs
        assert fc == "DJI"

        # DJI GS Pro .json
        f_gspro = td / "gspro.json"
        f_gspro.write_text(json.dumps({"app": "GS Pro", "waypoints": []}), encoding="utf-8")
        gcs, fc = GCSAnalyzer.identify_gcs_format(f_gspro)
        assert gcs is not None and "DJI GS Pro" in gcs
        assert fc == "DJI"

        # iNav .mission
        f_inav = td / "nav.mission"
        f_inav.write_text("1 1 0 16 0 0 0 0 19.133 72.913 40 1\n", encoding="utf-8")
        gcs, fc = GCSAnalyzer.identify_gcs_format(f_inav)
        assert gcs is not None and "iNav" in gcs
        assert fc is not None and ("Betaflight" in fc or "iNav" in fc)

        # MWP .mwp
        f_mwp = td / "flight.mwp"
        f_mwp.write_text("<mission><waypoint lat='19.13' lon='72.91' alt='50'/></mission>", encoding="utf-8")
        gcs, fc = GCSAnalyzer.identify_gcs_format(f_mwp)
        assert gcs is not None and ("mwp" in gcs or "iNav" in gcs)

        # Parrot FlightPlan .mavlink
        f_parrot = td / "plan.mavlink"
        f_parrot.write_text("QGC WPL 120\n0 1 0 22 0 0 0 0 19.13 72.91 30 1\n", encoding="utf-8")
        gcs, fc = GCSAnalyzer.identify_gcs_format(f_parrot)
        assert gcs is not None and "Parrot" in gcs
        assert fc is not None and "Parrot" in fc


# -----------------------------------------------------------------------------
# 2. Pure-Python MAVLink .tlog Decoding Tests
# -----------------------------------------------------------------------------

def test_parse_mavlink_tlog():
    """Construct synthetic MAVLink 1 / 2 binary packets prefixed with 64-bit microsecond timestamps."""
    with tempfile.NamedTemporaryFile(suffix=".tlog", delete=False) as f:
        tlog_path = Path(f.name)

    try:
        # Microsecond timestamp for 2026-09-14 10:00:00 UTC = 1789376400000000 us
        time_us = 1789376400000000
        buffer = bytearray()

        # Packet 1: HEARTBEAT (msg ID 0)
        hb_payload = struct.pack("<IBBBBB", 0, 2, 3, 1, 0, 3)
        hb_pkt = struct.pack(">Q", time_us) + b"\xfe\x09\x00\x01\x01\x00" + hb_payload + b"\x12\x34"
        buffer.extend(hb_pkt)

        # Packet 2: HOME_POSITION (msg ID 242) -> Operator / GCS Launch Location
        # Lat: 19.133400 * 1e7 = 191334000, Lon: 72.913300 * 1e7 = 729133000, Alt: 50.0m * 1000 = 50000
        home_payload = struct.pack("<iii", 191334000, 729133000, 50000) + (b"\x00" * 40)
        home_pkt = struct.pack(">Q", time_us + 1000000) + b"\xfe" + struct.pack("BBBBB", len(home_payload), 1, 1, 1, 242) + home_payload + b"\x56\x78"
        buffer.extend(home_pkt)

        # Packet 3: GLOBAL_POSITION_INT (msg ID 33) -> Telemetry point
        gpos_payload = struct.pack("<Iiiii", 1000, 191340000, 729140000, 55000, 5000) + struct.pack("<hhhh", 300, 400, 0, 9000)
        gpos_pkt = struct.pack(">Q", time_us + 2000000) + b"\xfe" + struct.pack("BBBBB", len(gpos_payload), 2, 1, 1, 33) + gpos_payload + b"\x9a\xbc"
        buffer.extend(gpos_pkt)

        # Packet 4: GPS_RAW_INT (msg ID 24) -> GPS Fix
        gps_payload = struct.pack("<Q", time_us + 3000000) + struct.pack("<BiiiHHHHB", 3, 191345000, 729145000, 60000, 100, 100, 500, 9000, 16)
        gps_pkt = struct.pack(">Q", time_us + 3000000) + b"\xfe" + struct.pack("BBBBB", len(gps_payload), 3, 1, 1, 24) + gps_payload + b"\xde\xf0"
        buffer.extend(gps_pkt)

        tlog_path.write_bytes(buffer)

        # Parse with pure-Python GCSAnalyzer
        telemetry, events, operator_locations, meta = GCSAnalyzer.parse_mavlink_tlog(tlog_path)
        assert len(telemetry) >= 2, "Should extract GLOBAL_POSITION_INT and GPS_RAW_INT points"
        assert meta["messages_decoded"] >= 3

        # Check operator location extracted from HOME_POSITION
        assert len(operator_locations) >= 1, "Should extract OperatorLocation from HOME_POSITION"
        op = operator_locations[0]
        assert pytest.approx(op.latitude, rel=1e-4) == 19.1334
        assert pytest.approx(op.longitude, rel=1e-4) == 72.9133
        assert pytest.approx(op.altitude_m, rel=1e-2) == 50.0
        assert "HOME_POSITION" in op.source

        # Check first telemetry point coordinates
        pt1 = telemetry[0]
        assert pytest.approx(pt1.latitude, rel=1e-4) == 19.134
        assert pytest.approx(pt1.longitude, rel=1e-4) == 72.914
    finally:
        if tlog_path.exists():
            tlog_path.unlink()


# -----------------------------------------------------------------------------
# 3. QGC WPL 110 Waypoints Parsing
# -----------------------------------------------------------------------------

def test_parse_qgc_wpl():
    with tempfile.NamedTemporaryFile(suffix=".waypoints", delete=False, mode="w", encoding="utf-8") as f:
        f.write("QGC WPL 110\n")
        f.write("0\t1\t0\t16\t0\t0\t0\t0\t19.133000\t72.913000\t25.0\t1\n") # Home (seq 0)
        f.write("1\t0\t3\t16\t0.000000\t0.000000\t0.000000\t0.000000\t19.134000\t72.914000\t50.0\t1\n") # WP 1
        f.write("2\t0\t3\t19\t10.000000\t0.000000\t0.000000\t0.000000\t19.135000\t72.915000\t55.0\t1\n") # WP 2 (LOITER_TIME 10s)
        f.write("3\t0\t3\t20\t0.000000\t0.000000\t0.000000\t0.000000\t0.000000\t0.000000\t0.0\t1\n") # RTL
        wpl_path = Path(f.name)

    try:
        plan, tele, evts, ops = GCSAnalyzer.parse_qgc_wpl(wpl_path)
        assert plan is not None
        assert "QGroundControl" in plan.gcs_name or "Mission Planner" in plan.gcs_name
        assert len(plan.waypoints) == 4
        assert plan.planned_home_lat is not None
        assert pytest.approx(plan.planned_home_lat, rel=1e-4) == 19.133
        assert pytest.approx(plan.planned_home_lon, rel=1e-4) == 72.913
        assert plan.waypoints[0].index == 0
        assert plan.waypoints[0].command == "HOME"
        assert plan.waypoints[1].index == 1
        assert plan.waypoints[1].command == "WAYPOINT"
        assert plan.waypoints[2].command == "LOITER_TIME"
        assert plan.waypoints[2].param1 == 10.0
        assert plan.waypoints[3].command == "RETURN_TO_LAUNCH"
        assert len(ops) >= 1
    finally:
        if wpl_path.exists():
            wpl_path.unlink()


# -----------------------------------------------------------------------------
# 4. QGroundControl JSON .plan Parsing
# -----------------------------------------------------------------------------

def test_parse_qgc_plan():
    plan_data = {
        "fileType": "Plan",
        "groundStation": "QGroundControl",
        "version": 1,
        "mission": {
            "plannedHomePosition": [19.1332, 72.9134, 30.0],
            "items": [
                {
                    "autoContinue": True,
                    "command": 16, # NAV_WAYPOINT
                    "doJumpId": 1,
                    "frame": 3,
                    "params": [0, 0, 0, None, 19.1350, 72.9150, 45.0],
                    "type": "SimpleItem"
                },
                {
                    "autoContinue": True,
                    "command": 178, # DO_CHANGE_SPEED
                    "params": [1, 8.5, -1, 0, 0, 0, 0],
                    "type": "SimpleItem"
                },
                {
                    "autoContinue": True,
                    "command": 16,
                    "params": [5, 0, 0, None, 19.1370, 72.9170, 60.0],
                    "type": "SimpleItem"
                }
            ]
        },
        "geoFence": {
            "polygons": [
                {
                    "inclusion": True,
                    "polygon": [
                        [19.130, 72.910],
                        [19.140, 72.910],
                        [19.140, 72.920],
                        [19.130, 72.920]
                    ]
                }
            ]
        },
        "rallyPoints": {
            "points": [
                [19.132, 72.912, 20.0]
            ]
        }
    }

    with tempfile.NamedTemporaryFile(suffix=".plan", delete=False, mode="w", encoding="utf-8") as f:
        json.dump(plan_data, f)
        plan_path = Path(f.name)

    try:
        plan, tele, evts, ops, fences = GCSAnalyzer.parse_qgc_plan(plan_path)
        assert plan is not None
        assert plan.gcs_name == "QGroundControl"
        assert len(plan.waypoints) >= 2
        assert plan.planned_home_lat is not None
        assert pytest.approx(plan.planned_home_lat, rel=1e-4) == 19.1332
        assert pytest.approx(plan.planned_home_lon, rel=1e-4) == 72.9134
        assert len(plan.geofence_polygons) == 1
        assert len(plan.geofence_polygons[0]) == 4
        assert plan.planned_max_altitude_m == 60.0
        assert len(ops) >= 1
        assert len(fences) >= 1
    finally:
        if plan_path.exists():
            plan_path.unlink()


# -----------------------------------------------------------------------------
# 5. DJI Pilot 2 WPML (.kml) Parsing
# -----------------------------------------------------------------------------

def test_parse_dji_wpml():
    wpml_xml = """<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2" xmlns:wpml="http://www.dji.com/wpmz/1.0.2">
  <Document>
    <wpml:author>DJI Pilot 2 Enterprise</wpml:author>
    <wpml:missionConfig>
      <wpml:flyToWaylineMode>safely</wpml:flyToWaylineMode>
      <wpml:takeOffSecurityHeight>20</wpml:takeOffSecurityHeight>
      <wpml:globalTransitionalSpeed>12</wpml:globalTransitionalSpeed>
    </wpml:missionConfig>
    <Folder>
      <wpml:templateType>waypoint</wpml:templateType>
      <Placemark>
        <Point>
          <coordinates>72.913500,19.133500,35.0</coordinates>
        </Point>
        <wpml:index>0</wpml:index>
        <wpml:executeHeight>35.0</wpml:executeHeight>
        <wpml:waypointSpeed>5.0</wpml:waypointSpeed>
        <wpml:waypointHeadingParam>
          <wpml:waypointHeadingMode>followWayline</wpml:waypointHeadingMode>
        </wpml:waypointHeadingParam>
      </Placemark>
      <Placemark>
        <Point>
          <coordinates>72.916000,19.136000,50.0</coordinates>
        </Point>
        <wpml:index>1</wpml:index>
        <wpml:executeHeight>50.0</wpml:executeHeight>
        <wpml:waypointSpeed>8.0</wpml:waypointSpeed>
      </Placemark>
    </Folder>
  </Document>
</kml>"""

    with tempfile.NamedTemporaryFile(suffix=".kml", delete=False, mode="w", encoding="utf-8") as f:
        f.write(wpml_xml)
        kml_path = Path(f.name)

    try:
        plan, tele, evts, ops = GCSAnalyzer.parse_dji_wpml(kml_path)
        assert plan is not None
        assert "DJI Pilot 2" in plan.gcs_name
        assert len(plan.waypoints) == 2
        assert pytest.approx(plan.waypoints[0].latitude, rel=1e-4) == 19.1335
        assert pytest.approx(plan.waypoints[0].longitude, rel=1e-4) == 72.9135
        assert plan.waypoints[0].altitude_m == 35.0
        assert plan.waypoints[0].speed_mps == 5.0
        assert pytest.approx(plan.waypoints[1].latitude, rel=1e-4) == 19.1360
        assert len(ops) >= 1
    finally:
        if kml_path.exists():
            kml_path.unlink()


# -----------------------------------------------------------------------------
# 6. DJI GS Pro JSON Parsing
# -----------------------------------------------------------------------------

def test_parse_dji_gspro():
    gspro_data = {
        "app": "GS Pro",
        "version": "2.0",
        "homeLocation": {"latitude": 19.1330, "longitude": 72.9130, "altitude": 20.0},
        "waypoints": [
            {"index": 1, "latitude": 19.1345, "longitude": 72.9145, "altitude": 40.0, "speed": 6.0},
            {"index": 2, "latitude": 19.1365, "longitude": 72.9165, "altitude": 55.0, "speed": 6.0}
        ]
    }

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w", encoding="utf-8") as f:
        json.dump(gspro_data, f)
        json_path = Path(f.name)

    try:
        plan, tele, evts, ops = GCSAnalyzer.parse_dji_gspro(json_path)
        assert plan is not None
        assert "DJI" in plan.gcs_name
        assert len(plan.waypoints) == 2
        assert plan.planned_home_lat is not None
        assert pytest.approx(plan.planned_home_lat, rel=1e-4) == 19.133
        assert plan.waypoints[0].index == 1
    finally:
        if json_path.exists():
            json_path.unlink()


# -----------------------------------------------------------------------------
# 7. iNav / MWP Waypoint Mission Parsing
# -----------------------------------------------------------------------------

def test_parse_inav_mission():
    inav_text = """1 1 0 16 0 0 0 0 19.133500 72.913500 30 1
2 0 3 16 0 0 0 0 19.135000 72.915000 50 1
3 0 3 16 0 0 0 0 19.136500 72.916500 50 1
4 0 3 20 0 0 0 0 0.000000 0.000000 0 1
"""
    with tempfile.NamedTemporaryFile(suffix=".mission", delete=False, mode="w", encoding="utf-8") as f:
        f.write(inav_text)
        mission_path = Path(f.name)

    try:
        plan, tele, evts, ops = GCSAnalyzer.parse_inav_mission(mission_path)
        assert plan is not None
        assert "iNav" in plan.gcs_name or "mwp" in plan.gcs_name
        assert len(plan.waypoints) >= 3
        assert plan.planned_home_lat is not None
        assert pytest.approx(plan.planned_home_lat, rel=1e-4) == 19.1335
        assert plan.waypoints[0].command == "WAYPOINT"
    finally:
        if mission_path.exists():
            mission_path.unlink()


# -----------------------------------------------------------------------------
# 8. Parrot FlightPlan (.mavlink) Parsing
# -----------------------------------------------------------------------------

def test_parse_parrot_flightplan():
    parrot_text = """QGC WPL 120
0 1 0 22 0 0 0 0 19.133000 72.913000 10.0 1
1 0 3 16 0 0 0 0 19.134500 72.914500 35.0 1
2 0 3 16 0 0 0 0 19.136000 72.916000 40.0 1
3 0 3 21 0 0 0 0 19.133000 72.913000 0.0 1
"""
    with tempfile.NamedTemporaryFile(suffix=".mavlink", delete=False, mode="w", encoding="utf-8") as f:
        f.write(parrot_text)
        fp_path = Path(f.name)

    try:
        plan, tele, evts, ops = GCSAnalyzer.parse_parrot_flightplan(fp_path)
        assert plan is not None
        assert "Parrot" in plan.gcs_name
        assert len(plan.waypoints) == 4
        assert plan.planned_home_lat is not None
        assert pytest.approx(plan.planned_home_lat, rel=1e-4) == 19.1330
    finally:
        if fp_path.exists():
            fp_path.unlink()


# -----------------------------------------------------------------------------
# 9. Mission Trajectory Compliance & Adherence Comparison
# -----------------------------------------------------------------------------

def test_compare_mission_trajectory():
    # 3 planned waypoints along a corridor
    wps = [
        PlannedWaypoint(index=1, command="WAYPOINT", latitude=19.1330, longitude=72.9130, altitude_m=30.0, speed_mps=5.0),
        PlannedWaypoint(index=2, command="WAYPOINT", latitude=19.1350, longitude=72.9150, altitude_m=40.0, speed_mps=5.0),
        PlannedWaypoint(index=3, command="WAYPOINT", latitude=19.1370, longitude=72.9170, altitude_m=50.0, speed_mps=5.0),
    ]
    plan = GCSMissionPlan(
        plan_id="SURVEY-A",
        gcs_name="QGroundControl",
        target_fc="PX4",
        file_name="survey.plan",
        waypoints=wps,
        total_planned_distance_m=600.0,
        planned_max_altitude_m=50.0
    )

    # Flown telemetry points closely tracking waypoints 1 and 2, but stopping before 3
    telemetry = [
        TelemetryPoint(timestamp_utc="2026-09-14T10:00:00Z", latitude=19.13302, longitude=72.91301, altitude_m=29.8, speed_mps=4.8), # Reached WP 1
        TelemetryPoint(timestamp_utc="2026-09-14T10:01:00Z", latitude=19.13400, longitude=72.91400, altitude_m=35.0, speed_mps=5.0),
        TelemetryPoint(timestamp_utc="2026-09-14T10:02:00Z", latitude=19.13503, longitude=72.91502, altitude_m=39.5, speed_mps=5.1), # Reached WP 2
        # Aborts / crashes here before WP 3
    ]

    comp = GCSAnalyzer.compare_mission_trajectory(plan, telemetry, acceptance_radius_m=25.0)
    assert comp["waypoints_total"] == 3
    assert comp["waypoints_reached"] == 2
    assert comp["mission_interrupted"] is True
    assert comp["compliance_score_pct"] == pytest.approx(66.7, rel=1e-1)
    assert comp["mean_deviation_meters"] > 0


# -----------------------------------------------------------------------------
# 10. Plugin Manager Integration Tests
# -----------------------------------------------------------------------------

def test_plugin_manager_gcs_routing():
    mgr = PluginManager()
    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)

        # ArduPilot plugin with .waypoints
        wpl_file = td / "test.waypoints"
        wpl_file.write_text("QGC WPL 110\n0 1 0 16 0 0 0 0 19.133 72.913 25 1\n1 0 3 16 0 0 0 0 19.135 72.915 40 1\n", encoding="utf-8")
        plat, tele, evts, meta = mgr.parse_evidence(wpl_file)
        assert plat == "ardupilot"
        assert len(tele) >= 1
        assert "ground_control_station" in meta

        # PX4 plugin with .plan
        plan_file = td / "px4.plan"
        plan_file.write_text(json.dumps({
            "groundStation": "QGroundControl",
            "mission": {
                "plannedHomePosition": [19.133, 72.913, 20.0],
                "items": [{"command": 16, "params": [0, 0, 0, None, 19.136, 72.916, 50.0], "type": "SimpleItem"}]
            }
        }), encoding="utf-8")
        plat, tele, evts, meta = mgr.parse_evidence(plan_file)
        assert plat in ("px4", "ardupilot")
        assert "ground_control_station" in meta

        # DJI plugin with .kml
        kml_file = td / "dji.kml"
        kml_file.write_text('<kml xmlns:wpml="http://www.dji.com/wpmz/1.0.2"><Folder><Placemark><Point><coordinates>72.913,19.133,30.0</coordinates></Point></Placemark></Folder></kml>', encoding="utf-8")
        plat, tele, evts, meta = mgr.parse_evidence(kml_file)
        assert plat == "dji"
        assert "ground_control_station" in meta

        # Betaflight plugin with .mission
        mission_file = td / "fpv.mission"
        mission_file.write_text("1 1 0 16 0 0 0 0 19.133 72.913 20 1\n2 0 3 16 0 0 0 0 19.136 72.916 40 1\n", encoding="utf-8")
        plat, tele, evts, meta = mgr.parse_evidence(mission_file)
        assert plat == "betaflight"
        assert "ground_control_station" in meta

        # Parrot plugin with .mavlink
        mavlink_file = td / "anafi.mavlink"
        mavlink_file.write_text("QGC WPL 120\n0 1 0 22 0 0 0 0 19.133 72.913 10 1\n1 0 3 16 0 0 0 0 19.136 72.916 30 1\n", encoding="utf-8")
        plat, tele, evts, meta = mgr.parse_evidence(mavlink_file)
        assert plat == "parrot"
        assert "ground_control_station" in meta


# -----------------------------------------------------------------------------
# 11. API Endpoints & Forensic Reporting Tests
# -----------------------------------------------------------------------------

def test_api_gcs_endpoints_and_reporting():
    # 1. Supported stations endpoint
    res = client.get("/api/gcs/supported-stations")
    assert res.status_code == 200
    stations = res.json()
    assert len(stations) >= 5
    station_names = [s["gcs_name"] for s in stations]
    assert any("Mission Planner" in n for n in station_names)
    assert any("QGroundControl" in n for n in station_names)
    assert any("DJI Pilot 2" in n for n in station_names)

    # 2. Ingest GCS Plan into a Case
    case_id = "API-GCS-TEST-01"
    client.post("/api/cases", json={
        "case_id": case_id,
        "case_name": "Autonomous GCS Airspace Survey",
        "investigator_name": "Forensic Inspector",
        "agency_name": "Drone Forensic Unit",
        "description": "GCS E2E Test"
    })

    plan_content = json.dumps({
        "fileType": "Plan",
        "groundStation": "QGroundControl",
        "version": 1,
        "mission": {
            "plannedHomePosition": [19.1334, 72.9133, 40.0],
            "items": [
                {
                    "autoContinue": True,
                    "command": 16,
                    "params": [0, 0, 0, None, 19.1350, 72.9150, 50.0],
                    "type": "SimpleItem"
                },
                {
                    "autoContinue": True,
                    "command": 16,
                    "params": [0, 0, 0, None, 19.1370, 72.9170, 60.0],
                    "type": "SimpleItem"
                }
            ]
        },
        "geoFence": {
            "polygons": [
                {
                    "inclusion": True,
                    "polygon": [[19.13, 72.91], [19.14, 72.91], [19.14, 72.92], [19.13, 72.92]]
                }
            ]
        }
    })

    ingest_res = client.post(
        f"/api/cases/{case_id}/ingest",
        files={"file": ("mission_plan.plan", plan_content.encode("utf-8"), "application/json")},
        data={"acquisition_type": "LOGICAL_EXTRACT", "actor": "QA Specialist"}
    )
    assert ingest_res.status_code == 200

    # 3. Retrieve GCS Analysis Result
    gcs_res = client.get(f"/api/cases/{case_id}/gcs")
    assert gcs_res.status_code == 200
    gcs_data = gcs_res.json()
    assert gcs_data["detected_gcs"] == "QGroundControl"
    assert len(gcs_data["operator_locations"]) >= 1
    assert pytest.approx(gcs_data["operator_locations"][0]["latitude"], rel=1e-4) == 19.1334
    assert len(gcs_data["mission_plans"][0]["waypoints"]) == 2

    # 4. Summary endpoint includes GCS & Operator data
    sum_res = client.get(f"/api/cases/{case_id}/summary")
    assert sum_res.status_code == 200
    sum_data = sum_res.json()
    assert sum_data["gcs_detected"] == "QGroundControl"
    assert sum_data["operator_location"] is not None
    assert pytest.approx(sum_data["operator_location"]["latitude"], rel=1e-4) == 19.1334

    # 5. HTML Forensic Report includes GCS section
    rep_res = client.get(f"/api/cases/{case_id}/report/html")
    assert rep_res.status_code == 200
    assert "Ground Control Station (GCS) &amp; Operator Forensics" in rep_res.text or "Ground Control Station (GCS) & Operator Forensics" in rep_res.text
    assert "QGroundControl" in rep_res.text
    assert "19.1334" in rep_res.text

    # 6. JSON Forensic Export includes GCS data
    json_rep = client.get(f"/api/cases/{case_id}/report/json")
    assert json_rep.status_code == 200
    assert "gcs_analysis" in json_rep.json()
    assert json_rep.json()["gcs_analysis"]["detected_gcs"] == "QGroundControl"

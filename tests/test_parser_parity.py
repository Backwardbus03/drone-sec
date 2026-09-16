import json
import pytest
from pathlib import Path
from dft.plugins.manager import PluginManager

SAMPLE_FILES = [
    "samples/ardupilot_sample.tlog",
    "samples/ardupilot_sample.bin",
    "samples/ardupilot_flight.log",
    "samples/dji_mavic3_telemetry.srt",
    "samples/betaflight_blackbox.txt",
    "samples/px4_mission.csv",
    "samples/parrot_anafi_flight.json"
]

@pytest.mark.parametrize("rel_path", SAMPLE_FILES)
def test_sample_parsing_parity(rel_path):
    p = Path(rel_path)
    if not p.exists():
        pytest.skip(f"Sample not found: {rel_path}")

    mgr = PluginManager()
    platform_id, telemetry, events, meta = mgr.parse_evidence(p)

    # Basic invariant assertions
    assert platform_id in ["ardupilot", "dji", "betaflight", "px4", "parrot"]
    assert isinstance(telemetry, list)
    assert isinstance(events, list)
    assert isinstance(meta, dict)

    if rel_path == "samples/ardupilot_sample.tlog":
        assert len(telemetry) == 12642
        assert len(events) == 1282
        assert telemetry[0].timestamp_utc.startswith("2015-07-18")
        assert pytest.approx(telemetry[0].latitude, rel=1e-5) == -35.2080891
        assert pytest.approx(telemetry[0].longitude, rel=1e-5) == 149.0435193
        assert pytest.approx(telemetry[-1].latitude, rel=1e-5) == -35.2080512
        assert pytest.approx(telemetry[-1].longitude, rel=1e-5) == 149.0435687

    elif rel_path == "samples/ardupilot_sample.bin":
        assert len(telemetry) == 1199
        assert len(events) == 5
        assert telemetry[0].timestamp_utc.startswith("2015-11-21")
        assert pytest.approx(telemetry[0].latitude, rel=1e-5) == -35.3640332
        assert pytest.approx(telemetry[0].longitude, rel=1e-5) == 149.1647457
        assert pytest.approx(telemetry[-1].latitude, rel=1e-5) == -35.3622797
        assert pytest.approx(telemetry[-1].longitude, rel=1e-5) == 149.1659262

    elif rel_path == "samples/ardupilot_flight.log":
        assert len(telemetry) == 6
        assert len(events) == 2

    elif rel_path == "samples/dji_mavic3_telemetry.srt":
        assert len(telemetry) == 9
        assert len(events) == 5

    elif rel_path == "samples/betaflight_blackbox.txt":
        assert len(telemetry) == 6
        assert len(events) == 2

    elif rel_path == "samples/px4_mission.csv":
        assert len(telemetry) == 7
        assert len(events) == 4

    elif rel_path == "samples/parrot_anafi_flight.json":
        assert len(telemetry) == 6
        assert len(events) == 4

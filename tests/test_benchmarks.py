"""
Automated unit and integration tests for Drone Forensic Toolkit (DFT) Benchmark Subsystem.
Verifies all 7 reference benchmark datasets (VTO Labs, DROP Phantom III, AirData UAV,
DroSev/DroNER, ArduPilot Suite, PX4/ALFA Suite, and UAV Media & Video Telemetry Suite),
media EXIF & video subtitle telemetry extraction, evaluator execution, and REST API endpoints.
"""

import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from dft.api.app import app
from dft.benchmarks.registry import BENCHMARK_REGISTRY, list_benchmarks, get_benchmark_by_id
from dft.benchmarks.evaluator import BenchmarkEvaluator
from dft.analysis.media import DroneMediaExtractor

client = TestClient(app)


def test_benchmark_registry_completeness():
    """Validates that all 7 reference benchmark datasets are registered with complete metadata."""
    benchmarks = list_benchmarks()
    assert len(benchmarks) == 7, f"Expected 7 benchmarks, got {len(benchmarks)}"

    expected_ids = [
        "vto-labs-drone-program",
        "drop-dji-phantom3",
        "airdata-uav-logs",
        "drosev-droner-mendeley",
        "ardupilot-flight-suite",
        "px4-alfa-anomaly-suite",
        "uav-media-exif-video-suite"
    ]

    for exp_id in expected_ids:
        b = get_benchmark_by_id(exp_id)
        assert b is not None, f"Benchmark {exp_id} missing from registry"
        assert len(b.name) > 5
        assert len(b.citation) > 10
        assert b.reference_url.startswith("http")
        assert len(b.target_platforms) >= 1
        assert len(b.evidence_types) >= 1
        assert len(b.toolkit_layers) >= 1
        assert len(b.metrics) >= 2
        assert len(b.sample_cases) >= 1
        assert len(b.forensic_challenges) >= 1


def test_evaluator_all_suites_execution():
    """Runs the full benchmark suite and verifies that all 7 suites pass with 100% compliance."""
    evaluator = BenchmarkEvaluator()
    suite_res = evaluator.run_all()

    assert suite_res.total_benchmarks == 7
    assert suite_res.benchmarks_passed == 7
    assert suite_res.all_passed is True
    assert suite_res.overall_score == 100.0
    assert "Standards Compliance: ISO/IEC 27037 & 27042" in suite_res.summary

    for r in suite_res.results:
        assert r.passed is True
        assert r.score == 100.0
        assert r.checks_passed == r.checks_run
        assert len(r.details) >= 3


def test_evaluator_individual_suites():
    """Tests execution of individual benchmark suites."""
    evaluator = BenchmarkEvaluator()

    # Test ArduPilot specifically
    ardu_res = evaluator.run_benchmark("ardupilot-flight-suite")
    assert ardu_res is not None
    assert ardu_res.passed is True
    assert ardu_res.score == 100.0
    assert any("DataFlash" in c["check"] for c in ardu_res.details)

    # Test PX4 specifically
    px4_res = evaluator.run_benchmark("px4-alfa-anomaly-suite")
    assert px4_res is not None
    assert px4_res.passed is True
    assert px4_res.score == 100.0
    assert any("PX4 ULog" in c["check"] for c in px4_res.details)

    # Test Media & Video suite specifically
    media_res = evaluator.run_benchmark("uav-media-exif-video-suite")
    assert media_res is not None
    assert media_res.passed is True
    assert media_res.score == 100.0
    assert any("EXIF" in c["check"] for c in media_res.details)
    assert any("Video Subtitle" in c["check"] for c in media_res.details)

    # Test unknown ID returns None
    assert evaluator.run_benchmark("non-existent-benchmark") is None


def test_drone_media_extractor_photo():
    """Validates EXIF metadata and GPS parsing on real or synthetic UAV photo."""
    photo_path = Path("benchmarks/data/drone_aerial_photo_ebee.jpg")
    if not photo_path.exists():
        pytest.skip("Real aerial drone photo not yet fetched in benchmarks/data")

    meta = DroneMediaExtractor.extract_photo_metadata(photo_path)
    assert meta["has_exif"] is True
    assert meta["has_gps"] is True
    assert meta["latitude"] is not None
    assert meta["longitude"] is not None
    assert meta["camera_model"] is not None
    # Real SenseFly eBee photo coordinate verification (around 41.22 N, -81.70 W)
    assert 40.0 <= meta["latitude"] <= 43.0
    assert -83.0 <= meta["longitude"] <= -80.0


def test_drone_media_extractor_video_srt(tmp_path):
    """Validates frame-by-frame telemetry extraction from DJI-style .SRT video subtitle streams."""
    srt_content = """1
00:00:01,000 --> 00:00:02,000
HOME(112.7930,-7.2840) 2024.11.10 03:09:29
GPS(112.7932,-7.2842,12) BAROMETER: 24.5M ISO:100 Shutter:1/500 Fnum:2.8

2
00:00:02,000 --> 00:00:03,000
HOME(112.7930,-7.2840) 2024.11.10 03:09:30
GPS(112.7935,-7.2845,14) BAROMETER: 28.2M ISO:100 Shutter:1/500 Fnum:2.8
"""
    test_srt = tmp_path / "DJI_0042.SRT"
    test_srt.write_text(srt_content, encoding="utf-8")

    telemetry = DroneMediaExtractor.extract_video_subtitle_telemetry(test_srt)
    assert len(telemetry) == 2
    assert telemetry[0]["frame_index"] == 1
    assert telemetry[0]["latitude"] == -7.2842
    assert telemetry[0]["longitude"] == 112.7932
    assert telemetry[0]["altitude_m"] == 24.5
    assert telemetry[0]["camera_settings"]["iso"] == "100"

    assert telemetry[1]["frame_index"] == 2
    assert telemetry[1]["latitude"] == -7.2845
    assert telemetry[1]["longitude"] == 112.7935
    assert telemetry[1]["altitude_m"] == 28.2


def test_api_list_benchmarks():
    """Tests GET /api/benchmarks endpoint."""
    res = client.get("/api/benchmarks")
    assert res.status_code == 200
    data = res.json()
    assert len(data) == 7

    ids = [b["id"] for b in data]
    assert "vto-labs-drone-program" in ids
    assert "ardupilot-flight-suite" in ids
    assert "px4-alfa-anomaly-suite" in ids
    assert "uav-media-exif-video-suite" in ids


def test_api_get_single_benchmark():
    """Tests GET /api/benchmarks/{id} endpoint."""
    res = client.get("/api/benchmarks/uav-media-exif-video-suite")
    assert res.status_code == 200
    data = res.json()
    assert data["id"] == "uav-media-exif-video-suite"
    assert "Photo" in data["name"]
    assert "EXIF" in data["name"]

    # 404 test
    not_found = client.get("/api/benchmarks/unknown-id")
    assert not_found.status_code == 404


def test_api_run_benchmark_endpoint():
    """Tests POST /api/benchmarks/run endpoint."""
    # Run full suite
    res = client.post("/api/benchmarks/run", json={})
    assert res.status_code == 200
    data = res.json()
    assert data["mode"] == "FULL_SUITE"
    assert data["total_benchmarks"] == 7
    assert data["benchmarks_passed"] == 7
    assert data["all_passed"] is True

    # Run single benchmark
    res_single = client.post("/api/benchmarks/run", json={"benchmark_id": "uav-media-exif-video-suite"})
    assert res_single.status_code == 200
    single_data = res_single.json()
    assert single_data["mode"] == "SINGLE_BENCHMARK"
    assert single_data["benchmark_id"] == "uav-media-exif-video-suite"
    assert single_data["passed"] is True
    assert single_data["score"] == 100.0


def test_api_fetch_real_data_endpoint():
    """Tests POST /api/benchmarks/fetch-real-data endpoint."""
    res = client.post("/api/benchmarks/fetch-real-data")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] in ["SUCCESS", "PARTIAL"]
    assert "destination_directory" in data
    assert data["total_downloaded"] >= 1

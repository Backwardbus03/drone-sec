"""
Automated unit and integration tests for real-world geo-restricted airspaces
(Airports, Aerodromes, Military Airbases, Government Secretariats, Nuclear/Strategic Sites, Prisons).
"""

import pytest
from fastapi.testclient import TestClient
from dft.api.app import app
from dft.core.models import TelemetryPoint
from dft.analysis.geofence import GeofenceEngine
from dft.analysis.restricted_spaces import (
    REAL_WORLD_RESTRICTED_SPACES,
    get_all_restricted_spaces,
    get_catalog_filtered,
    get_preset_by_id,
    get_default_core_presets
)

client = TestClient(app)


def test_restricted_spaces_catalog_integrity():
    """Validates that all real-world restricted airspaces have valid coordinates and schema."""
    all_spaces = get_all_restricted_spaces()
    assert len(all_spaces) >= 30, f"Expected at least 30 real-world spaces, got {len(all_spaces)}"

    categories = {z.category for z in all_spaces}
    expected_categories = {"AIRPORT", "AIRDROME", "MILITARY_AIRFORCE", "GOVERNMENT", "STRATEGIC_NUCLEAR", "PRISON"}
    for exp in expected_categories:
        assert exp in categories, f"Category '{exp}' missing from real-world restricted spaces"

    for z in all_spaces:
        assert z.zone_id.startswith("ZONE-")
        assert len(z.name) > 3
        assert z.zone_class in ("RED", "YELLOW", "GREEN")
        assert z.authority is not None, f"Zone {z.zone_id} missing authority"

        if z.zone_type == "circle":
            assert -90.0 <= z.center_lat <= 90.0
            assert -180.0 <= z.center_lon <= 180.0
            assert z.radius_meters > 0.0
        elif z.zone_type == "polygon":
            assert len(z.coordinates) >= 3
            for pt in z.coordinates:
                assert -90.0 <= pt[0] <= 90.0
                assert -180.0 <= pt[1] <= 180.0


def test_restricted_spaces_filtering():
    """Validates catalog filtering by category and region."""
    airports = get_catalog_filtered(category="AIRPORT")
    assert len(airports) >= 8
    for a in airports:
        assert a.category == "AIRPORT"

    mumbai_spaces = get_catalog_filtered(city_region="Mumbai / MMR")
    assert len(mumbai_spaces) >= 7
    for s in mumbai_spaces:
        assert s.city_region == "Mumbai / MMR"

    # Specific lookup
    bom = get_preset_by_id("ZONE-AIRPORT-BOM")
    assert bom is not None
    assert "Chhatrapati Shivaji Maharaj" in bom.name
    assert bom.category == "AIRPORT"
    assert bom.zone_class == "RED"


def test_geofence_engine_default_presets():
    """Ensures GeofenceEngine initializes with core real-world presets and imports correctly."""
    engine = GeofenceEngine()
    zone_ids = {z.zone_id for z in engine.zones}
    assert "ZONE-AIRPORT-BOM" in zone_ids
    assert "ZONE-AIRDROME-VAJJ" in zone_ids
    assert "ZONE-GOV-MANTRALAYA" in zone_ids
    assert "ZONE-STRAT-BARC" in zone_ids
    assert "ZONE-BUFFER-IITB" in zone_ids

    # Test importing a specific preset
    del_airport = engine.import_preset("ZONE-AIRPORT-DEL")
    assert del_airport is not None
    assert "ZONE-AIRPORT-DEL" in {z.zone_id for z in engine.zones}

    # Test loading all presets
    total_added = engine.load_all_presets()
    assert total_added > 10
    assert len(engine.zones) >= len(REAL_WORLD_RESTRICTED_SPACES)


def test_geofence_breach_real_world_detection():
    """Simulates drone flight near Mumbai CSMI and IIT Bombay to verify breach identification."""
    engine = GeofenceEngine()

    telemetry = [
        # Point 1: Inside CSMI Airport 5km Red Zone (19.0896, 72.8656) at 40m altitude -> CRITICAL breach
        TelemetryPoint(timestamp_utc="2026-09-13T12:00:00Z", latitude=19.0900, longitude=72.8660, altitude_m=40.0),
        # Point 2: Inside IIT Bombay campus at 75m altitude (ceiling is 60m) -> CEILING_EXCEEDED
        TelemetryPoint(timestamp_utc="2026-09-13T12:05:00Z", latitude=19.1334, longitude=72.9133, altitude_m=75.0),
        # Point 3: Inside IIT Bombay campus at 30m altitude (under 60m ceiling) -> BOUNDARY_ENTRY
        TelemetryPoint(timestamp_utc="2026-09-13T12:06:00Z", latitude=19.1334, longitude=72.9133, altitude_m=30.0)
    ]

    violations = engine.evaluate_telemetry(telemetry)
    assert len(violations) >= 2

    # Check that CSMI breach was flagged
    csmi_breaches = [v for v in violations if v.zone_id == "ZONE-AIRPORT-BOM"]
    assert len(csmi_breaches) >= 1
    assert csmi_breaches[0].severity == "CRITICAL"
    assert csmi_breaches[0].category == "AIRPORT"
    assert "DGCA / AAI" in (csmi_breaches[0].authority or "")

    # Check that IITB ceiling breach was flagged
    iitb_breaches = [v for v in violations if v.zone_id == "ZONE-BUFFER-IITB" and v.violation_type == "CEILING_EXCEEDED"]
    assert len(iitb_breaches) >= 1


def test_api_real_world_catalog_and_import():
    """Tests FastAPI endpoints for querying catalog and importing presets into a case."""
    # 1. Fetch catalog
    cat_res = client.get("/api/geofence/catalog")
    assert cat_res.status_code == 200
    catalog = cat_res.json()
    assert len(catalog) >= 30

    # 2. Filter catalog via API
    filter_res = client.get("/api/geofence/catalog?category=GOVERNMENT")
    assert filter_res.status_code == 200
    gov_spaces = filter_res.json()
    assert len(gov_spaces) >= 5
    for g in gov_spaces:
        assert g["category"] == "GOVERNMENT"

    # 3. Create case
    case_id = "REAL-WORLD-TEST-01"
    create_res = client.post("/api/cases", json={
        "case_id": case_id,
        "case_name": "Real-World Restricted Airspace Test",
        "investigator_name": "Special Agent Forensics",
        "agency_name": "Aviation Safety Directorate"
    })
    assert create_res.status_code == 200

    # 4. Import a single preset (e.g. Rashtrapati Bhavan / Parliament)
    import_res = client.post(f"/api/cases/{case_id}/geofence/import-preset/ZONE-GOV-CENTRALVISTA")
    assert import_res.status_code == 200
    data = import_res.json()
    assert data["status"] == "IMPORTED"
    assert data["zone"]["zone_id"] == "ZONE-GOV-CENTRALVISTA"

    # 5. Bulk-import all presets
    bulk_res = client.post(f"/api/cases/{case_id}/geofence/load-all-presets")
    assert bulk_res.status_code == 200
    bulk_data = bulk_res.json()
    assert bulk_data["status"] == "ALL_PRESETS_LOADED"
    assert bulk_data["total_zones"] >= 30

    # 6. Verify zones list
    zones_res = client.get(f"/api/cases/{case_id}/geofence/zones")
    assert zones_res.status_code == 200
    assert len(zones_res.json()) >= 30

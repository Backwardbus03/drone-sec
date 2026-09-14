"""
FastAPI Server for Drone Forensic Toolkit (DFT).
REST API backend exposing cases, evidence ingestion, telemetry, geofencing, timeline, and reporting.
"""

from pathlib import Path
from typing import List, Dict, Any, Optional
import base64
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from dft.core.models import (
    CaseMetadata, EvidenceItem, TelemetryPoint, FlightEvent,
    GeofenceZone, GeofenceViolation, AnomalyReport, FlightSummary, AuditLogEntry,
    MediaCapture, PlannedWaypoint, GCSMissionPlan, OperatorLocation, GCSAnalysisResult
)
from dft.core.hashing import compute_hashes
from dft.core.chain_of_custody import ChainOfCustodyManager
from dft.core.write_blocker import WriteBlockController
from dft.plugins.manager import PluginManager
from dft.analysis.geofence import GeofenceEngine
from dft.analysis.flight_path import FlightPathAnalyzer
from dft.analysis.timeline import TimelineReconstructor
from dft.analysis.anomaly import AnomalyDetector
from dft.analysis.media_import import process_media_file
from dft.analysis.gcs import GCSAnalyzer
from dft.reporting.generator import ForensicReportGenerator

from dft.analysis.restricted_spaces import (
    get_all_restricted_spaces,
    get_catalog_filtered,
    get_preset_by_id
)

app = FastAPI(
    title="Drone Forensic Toolkit (DFT) API",
    description="Indigenous UAV Digital Forensics Framework compliant with ISO/IEC 27037:2012",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Persistent In-Memory Case Registry & Cache
BASE_DATA_DIR = Path("forensic_cases_vault")
BASE_DATA_DIR.mkdir(parents=True, exist_ok=True)

coc_db = ChainOfCustodyManager(BASE_DATA_DIR / "master_audit_trail.sqlite")
plugin_mgr = PluginManager()

# In-Memory state caches
CASES_STORE: Dict[str, CaseMetadata] = {}
CASE_EVIDENCE: Dict[str, List[EvidenceItem]] = {}
CASE_MEDIA: Dict[str, List[MediaCapture]] = {}
CASE_TELEMETRY: Dict[str, List[TelemetryPoint]] = {}
CASE_EVENTS: Dict[str, List[FlightEvent]] = {}
CASE_GEOFENCE_ENGINES: Dict[str, GeofenceEngine] = {}
CASE_VIOLATIONS: Dict[str, List[GeofenceViolation]] = {}
CASE_ANOMALIES: Dict[str, List[AnomalyReport]] = {}
CASE_METADATA_EXTRA: Dict[str, Dict[str, Any]] = {}
CASE_GCS_DATA: Dict[str, GCSAnalysisResult] = {}


class CreateCaseRequest(BaseModel):
    case_id: str
    case_name: str
    investigator_name: str
    agency_name: str
    description: Optional[str] = ""


class AddZoneRequest(BaseModel):
    name: str
    zone_type: str = "polygon"
    coordinates: List[List[float]] = []
    center_lat: Optional[float] = None
    center_lon: Optional[float] = None
    radius_meters: Optional[float] = None
    max_altitude_m: Optional[float] = None
    description: Optional[str] = None
    category: Optional[str] = "CUSTOM"
    zone_class: Optional[str] = "RED"
    authority: Optional[str] = None
    city_region: Optional[str] = None


@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
def get_dashboard():
    dashboard_path = Path("dft/web/dashboard.html")
    if dashboard_path.exists():
        return HTMLResponse(content=dashboard_path.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Drone Forensic Toolkit (DFT) API Running</h1><p><a href='/docs'>Swagger API Docs</a></p>")


@app.get("/samples/{filename}")
def get_sample_file(filename: str):
    p = Path("samples") / filename
    if not p.exists():
        raise HTTPException(status_code=404, detail=f"Sample file {filename} not found.")
    return Response(content=p.read_bytes(), media_type="application/octet-stream")


@app.get("/api/info")
def index_info():
    return {
        "toolkit": "Drone Forensic Toolkit (DFT)",
        "version": "1.0.0",
        "standards": ["ISO/IEC 27037:2012", "ISO/IEC 27042:2015"],
        "status": "OPERATIONAL",
        "docs_url": "/docs",
        "ui_url": "/dashboard"
    }


@app.get("/api/system/health")
def system_health():
    wb_sample = WriteBlockController.verify_read_only_status(BASE_DATA_DIR)
    return {
        "status": "HEALTHY",
        "plugins_count": len(plugin_mgr.list_plugins()),
        "supported_plugins": plugin_mgr.list_plugins(),
        "storage_vault": str(BASE_DATA_DIR.resolve()),
        "software_write_block_capability": wb_sample["canary_write_blocked"]
    }


# --- CASE MANAGEMENT ---

@app.post("/api/cases", response_model=CaseMetadata)
def create_case(req: CreateCaseRequest):
    case_id = req.case_id.strip()
    if case_id in CASES_STORE:
        raise HTTPException(status_code=400, detail=f"Case ID {case_id} already exists.")

    case = CaseMetadata(
        case_id=case_id,
        case_name=req.case_name,
        investigator_name=req.investigator_name,
        agency_name=req.agency_name,
        description=req.description
    )

    CASES_STORE[case_id] = case
    CASE_EVIDENCE[case_id] = []
    CASE_MEDIA[case_id] = []
    CASE_TELEMETRY[case_id] = []
    CASE_EVENTS[case_id] = []
    CASE_GEOFENCE_ENGINES[case_id] = GeofenceEngine()
    CASE_VIOLATIONS[case_id] = []
    CASE_ANOMALIES[case_id] = []
    CASE_METADATA_EXTRA[case_id] = {}
    CASE_STORE_GCS = GCSAnalysisResult(
        detected_gcs="NONE",
        associated_fc="NONE",
        gcs_artifacts=[],
        operator_locations=[],
        mission_plans=[]
    )
    CASE_GCS_DATA[case_id] = CASE_STORE_GCS

    coc_db.log_action(
        case_id=case_id,
        actor=req.investigator_name,
        action="CASE_CREATED",
        details=f"New forensic case initialized: '{req.case_name}' under {req.agency_name}"
    )

    return case


@app.get("/api/cases", response_model=List[CaseMetadata])
def list_cases():
    return list(CASES_STORE.values())


@app.get("/api/cases/{case_id}")
def get_case(case_id: str):
    if case_id not in CASES_STORE:
        raise HTTPException(status_code=404, detail="Case not found.")

    is_valid_chain, error_msg = coc_db.verify_chain(case_id)
    gcs_info = CASE_GCS_DATA.get(case_id)
    return {
        "case": CASES_STORE[case_id],
        "evidence_count": len(CASE_EVIDENCE.get(case_id, [])),
        "media_count": len(CASE_MEDIA.get(case_id, [])),
        "telemetry_count": len(CASE_TELEMETRY.get(case_id, [])),
        "events_count": len(CASE_EVENTS.get(case_id, [])),
        "violations_count": len(CASE_VIOLATIONS.get(case_id, [])),
        "gcs_detected": gcs_info.detected_gcs if (gcs_info and gcs_info.detected_gcs != "NONE") else None,
        "operator_locations_count": len(gcs_info.operator_locations) if gcs_info else 0,
        "mission_plans_count": len(gcs_info.mission_plans) if gcs_info else 0,
        "chain_of_custody_verified": is_valid_chain,
        "chain_error": error_msg
    }


@app.get("/api/cases/{case_id}/audit-trail", response_model=List[AuditLogEntry])
def get_audit_trail(case_id: str):
    return coc_db.get_entries(case_id)


# --- EVIDENCE INGESTION ---

@app.post("/api/cases/{case_id}/ingest")
async def ingest_evidence(
    case_id: str,
    file: UploadFile = File(...),
    acquisition_type: str = Form("LOGICAL_EXTRACT"),
    actor: str = Form("Forensic Examiner")
):
    if case_id not in CASES_STORE:
        raise HTTPException(status_code=404, detail="Case not found.")

    case_folder = BASE_DATA_DIR / case_id
    case_folder.mkdir(parents=True, exist_ok=True)

    dest_path = case_folder / file.filename

    # Save uploaded file (clear read-only bit if re-uploading)
    if dest_path.exists():
        try:
            import os, stat
            os.chmod(dest_path, stat.S_IWRITE)
        except Exception:
            pass

    content = await file.read()
    with open(dest_path, "wb") as f:
        f.write(content)

    # 1. Enforce Software Read-Only
    WriteBlockController.enforce_file_read_only(dest_path)
    wb_status = WriteBlockController.verify_read_only_status(dest_path)

    # 2. Compute Dual Hashes
    manifest = compute_hashes(dest_path)

    # 3. Parse with Plugin Engine
    platform_id, telemetry, events, meta = plugin_mgr.parse_evidence(dest_path)

    # 4. Ingest and create EvidenceItem
    item_id = f"EV-{len(CASE_EVIDENCE[case_id]) + 1:03d}"
    evidence = EvidenceItem(
        item_id=item_id,
        case_id=case_id,
        file_name=file.filename,
        source_path=str(dest_path),
        file_size_bytes=manifest.byte_count,
        hashes=manifest,
        acquisition_type=acquisition_type,  # type: ignore
        write_block_verified=wb_status["canary_write_blocked"],
        drone_platform=platform_id
    )

    CASE_EVIDENCE[case_id].append(evidence)
    CASE_TELEMETRY[case_id].extend(telemetry)
    CASE_EVENTS[case_id].extend(events)
    CASE_METADATA_EXTRA[case_id].update(meta)

    # 4.5. Process Ground Control Station (GCS) Evidence
    gcs_format, gcs_fc = GCSAnalyzer.identify_gcs_format(dest_path)
    gcs_name_detected = gcs_format or meta.get("ground_control_station")

    if case_id not in CASE_GCS_DATA:
        CASE_GCS_DATA[case_id] = GCSAnalysisResult(
            detected_gcs=gcs_name_detected or "NONE",
            associated_fc=gcs_fc or platform_id,
            gcs_artifacts=[]
        )

    if gcs_name_detected:
        gcs_entry = CASE_GCS_DATA[case_id]
        if gcs_entry.detected_gcs == "NONE" or gcs_name_detected:
            gcs_entry.detected_gcs = gcs_name_detected
        if gcs_entry.associated_fc == "NONE" or gcs_fc:
            gcs_entry.associated_fc = gcs_fc or platform_id
        if file.filename not in gcs_entry.gcs_artifacts:
            gcs_entry.gcs_artifacts.append(file.filename)

        # Check operator location in metadata
        if meta.get("operator_location"):
            op_dict = meta["operator_location"]
            op_loc = OperatorLocation(**op_dict)
            if not any(abs(ol.latitude - op_loc.latitude) < 0.00001 and abs(ol.longitude - op_loc.longitude) < 0.00001 for ol in gcs_entry.operator_locations):
                gcs_entry.operator_locations.append(op_loc)

        # Extract mission plans from supported GCS files
        ext = dest_path.suffix.lower()
        if ext in [".waypoints", ".txt"]:
            try:
                plan, _, _, _ = GCSAnalyzer.parse_qgc_wpl(dest_path)
                if plan.waypoints:
                    gcs_entry.mission_plans.append(plan)
            except Exception:
                pass
        elif ext == ".plan":
            try:
                plan, _, _, _, geofs = GCSAnalyzer.parse_qgc_plan(dest_path)
                if plan.waypoints:
                    gcs_entry.mission_plans.append(plan)
                for gz in geofs:
                    CASE_GEOFENCE_ENGINES[case_id].add_zone(gz)
            except Exception:
                pass
        elif ext in [".kmz", ".kml"] and ("wpml" in str(dest_path).lower() or gcs_format == "DJI Pilot 2 (WPML)"):
            try:
                plan, _, _, _ = GCSAnalyzer.parse_dji_wpml(dest_path)
                if plan.waypoints:
                    gcs_entry.mission_plans.append(plan)
            except Exception:
                pass
        elif ext in [".mission", ".mwp", ".xml"]:
            try:
                plan, _, _, _ = GCSAnalyzer.parse_inav_mission(dest_path)
                if plan.waypoints:
                    gcs_entry.mission_plans.append(plan)
            except Exception:
                pass
        elif ext == ".mavlink":
            try:
                plan, _, _, _ = GCSAnalyzer.parse_parrot_flightplan(dest_path)
                if plan.waypoints:
                    gcs_entry.mission_plans.append(plan)
            except Exception:
                pass

    # Trajectory comparison if both planned mission and flight telemetry exist
    if case_id in CASE_GCS_DATA and CASE_GCS_DATA[case_id].mission_plans and CASE_TELEMETRY[case_id]:
        first_plan = CASE_GCS_DATA[case_id].mission_plans[0]
        comp = GCSAnalyzer.compare_mission_trajectory(first_plan, CASE_TELEMETRY[case_id])
        CASE_GCS_DATA[case_id].mission_comparison = comp

    # 5. Run Geofence & Anomaly Engines
    geo_engine = CASE_GEOFENCE_ENGINES[case_id]
    violations = geo_engine.evaluate_telemetry(CASE_TELEMETRY[case_id])
    CASE_VIOLATIONS[case_id] = violations

    anomalies = AnomalyDetector.inspect(CASE_TELEMETRY[case_id], CASE_EVENTS[case_id])
    CASE_ANOMALIES[case_id] = anomalies

    # 6. Log to Chain of Custody
    coc_db.log_action(
        case_id=case_id,
        actor=actor,
        action="EVIDENCE_INGESTED",
        details=f"Ingested {file.filename} ({manifest.byte_count} bytes). Platform: {platform_id}. SHA-256: {manifest.sha256[:12]}...",
        evidence_item_id=item_id
    )

    gcs_res = CASE_GCS_DATA.get(case_id)
    return {
        "evidence_item": evidence,
        "platform_detected": platform_id,
        "platform": platform_id,
        "telemetry_points_extracted": len(telemetry),
        "events_extracted": len(events),
        "violations_detected": len(violations),
        "anomalies_detected": len(anomalies),
        "gcs_detected": gcs_res.detected_gcs if (gcs_res and gcs_res.detected_gcs != "NONE") else None,
        "operator_locations_found": len(gcs_res.operator_locations) if gcs_res else 0,
        "mission_plans_found": len(gcs_res.mission_plans) if gcs_res else 0,
        "mission_compliance_pct": gcs_res.mission_comparison.get("compliance_score_pct") if (gcs_res and gcs_res.mission_comparison) else None
    }


# --- MEDIA EVIDENCE INGESTION & SYNCHRONIZATION ---

@app.post("/api/cases/{case_id}/ingest-media")
async def ingest_media(
    case_id: str,
    file: UploadFile = File(...),
    capture_timestamp: Optional[str] = Form(None),
    actor: str = Form("Forensic Examiner")
):
    """
    Ingests UAV media files (MP4, MOV, JPEG, PNG, TIFF, DNG).
    Extracts metadata, timestamps, and representative frames.
    Checks for overlap with flight telemetry and synchronizes capture events onto the master timeline.
    """
    if case_id not in CASES_STORE:
        raise HTTPException(status_code=404, detail="Case not found.")

    case_folder = BASE_DATA_DIR / case_id / "media"
    case_folder.mkdir(parents=True, exist_ok=True)

    dest_path = case_folder / file.filename
    if dest_path.exists():
        try:
            import os, stat
            os.chmod(dest_path, stat.S_IWRITE)
        except Exception:
            pass

    content = await file.read()
    with open(dest_path, "wb") as f:
        f.write(content)

    # 1. Software Write-Block
    WriteBlockController.enforce_file_read_only(dest_path)
    wb_status = WriteBlockController.verify_read_only_status(dest_path)

    # 2. Process Media & Check Overlap
    if case_id not in CASE_MEDIA:
        CASE_MEDIA[case_id] = []

    item_id = f"EV-MED-{len(CASE_MEDIA[case_id]) + 1:03d}"
    telemetry = CASE_TELEMETRY.get(case_id, [])
    media_cap, flight_event = process_media_file(
        dest_path, case_id, item_id, telemetry, client_timestamp=capture_timestamp
    )

    # 3. Register in Master Evidence Vault as MEDIA_IMPORT
    evidence = EvidenceItem(
        item_id=item_id,
        case_id=case_id,
        file_name=file.filename,
        source_path=str(dest_path),
        file_size_bytes=media_cap.file_size_bytes,
        hashes=media_cap.hashes,
        acquisition_type="MEDIA_IMPORT",
        write_block_verified=wb_status["canary_write_blocked"],
        drone_platform=f"{media_cap.media_type}_MEDIA"
    )
    CASE_EVIDENCE[case_id].append(evidence)
    CASE_MEDIA[case_id].append(media_cap)

    # 3.5. If E01 container was created for overlapping media, register in Evidence Vault
    eo1_evidence = None
    if media_cap.has_e01 and media_cap.e01_path:
        eo1_path = Path(media_cap.e01_path)
        eo1_item_id = f"{item_id}-EO1"
        eo1_evidence = EvidenceItem(
            item_id=eo1_item_id,
            case_id=case_id,
            file_name=eo1_path.name,
            source_path=str(eo1_path),
            file_size_bytes=media_cap.e01_hashes.byte_count if media_cap.e01_hashes else eo1_path.stat().st_size,
            hashes=media_cap.e01_hashes or compute_hashes(eo1_path),
            acquisition_type="PHYSICAL_IMAGE",
            write_block_verified=True,
            drone_platform=f"{media_cap.media_type}_EO1"
        )
        CASE_EVIDENCE[case_id].append(eo1_evidence)

        coc_db.log_action(
            case_id=case_id,
            actor=actor,
            action="FORENSIC_EO1_IMAGE_CREATED",
            details=(
                f"Generated bit-exact .eo1 forensic container for overlapping flight media "
                f"'{file.filename}' -> '{eo1_path.name}'. "
                f"SHA-256: {media_cap.e01_hashes.sha256[:16] if media_cap.e01_hashes else 'N/A'}..."
            ),
            evidence_item_id=eo1_item_id
        )

    # 4. If synchronized with flight window, inject into master event timeline
    if flight_event:
        CASE_EVENTS[case_id].append(flight_event)
        try:
            CASE_EVENTS[case_id].sort(key=lambda e: e.timestamp_utc)
        except Exception:
            pass

    # 5. Chain of Custody logging
    coc_db.log_action(
        case_id=case_id,
        actor=actor,
        action="MEDIA_EVIDENCE_INGESTED",
        details=(
            f"Ingested {media_cap.media_type} '{file.filename}' ({media_cap.file_size_bytes} bytes). "
            f"Overlap with telemetry: {media_cap.has_telemetry_overlap}. "
            f"SHA-256: {media_cap.hashes.sha256[:12]}..."
        ),
        evidence_item_id=item_id
    )

    return {
        "status": "SUCCESS",
        "media_item": media_cap,
        "has_overlap": media_cap.has_telemetry_overlap,
        "has_e01": media_cap.has_e01,
        "e01_path": media_cap.e01_path,
        "e01_hashes": media_cap.e01_hashes,
        "flight_event_created": flight_event is not None,
        "flight_event": flight_event,
        "time_delta_sec": media_cap.time_delta_sec,
        "matched_coordinates": {
            "latitude": media_cap.matched_latitude,
            "longitude": media_cap.matched_longitude,
            "altitude_m": media_cap.matched_altitude_m
        } if media_cap.has_telemetry_overlap else None,
        "evidence_item": evidence,
        "eo1_evidence_item": eo1_evidence
    }


@app.get("/api/cases/{case_id}/media", response_model=List[MediaCapture])
def get_case_media(case_id: str):
    """Returns all ingested media captures for the specified case."""
    if case_id not in CASES_STORE:
        raise HTTPException(status_code=404, detail="Case not found.")
    return CASE_MEDIA.get(case_id, [])


@app.get("/api/cases/{case_id}/media/{item_id}/thumbnail")
def get_media_thumbnail(case_id: str, item_id: str):
    """Streams the extracted JPEG thumbnail image bytes for a media item."""
    if case_id not in CASES_STORE:
        raise HTTPException(status_code=404, detail="Case not found.")
    media_items = CASE_MEDIA.get(case_id, [])
    target = next((m for m in media_items if m.item_id == item_id), None)
    if not target or not target.thumbnail_base64:
        raise HTTPException(status_code=404, detail="Thumbnail not available.")

    img_bytes = base64.b64decode(target.thumbnail_base64)
    return Response(content=img_bytes, media_type="image/jpeg")


@app.get("/api/cases/{case_id}/media/{item_id}/e01")
def download_media_e01(case_id: str, item_id: str):
    """Downloads the bit-exact .eo1 forensic container for overlapping media evidence."""
    if case_id not in CASES_STORE:
        raise HTTPException(status_code=404, detail="Case not found.")
    media_items = CASE_MEDIA.get(case_id, [])
    target = next((m for m in media_items if m.item_id == item_id), None)
    if not target or not target.e01_path:
        raise HTTPException(status_code=404, detail="E01 container not found for this media item.")
    e01_file = Path(target.e01_path)
    if not e01_file.exists():
        raise HTTPException(status_code=404, detail="E01 container file missing from storage.")
    with open(e01_file, "rb") as f:
        content = f.read()
    return Response(
        content=content,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{e01_file.name}"'}
    )


# --- TELEMETRY & FLIGHT ANALYSIS ---

@app.get("/api/cases/{case_id}/telemetry")
def get_telemetry(case_id: str):
    if case_id not in CASES_STORE:
        raise HTTPException(status_code=404, detail="Case not found.")
    return CASE_TELEMETRY.get(case_id, [])


@app.get("/api/cases/{case_id}/geojson")
def get_geojson(case_id: str):
    pts = CASE_TELEMETRY.get(case_id, [])
    return FlightPathAnalyzer.export_geojson(pts)


@app.get("/api/cases/{case_id}/kml")
def get_kml(case_id: str):
    pts = CASE_TELEMETRY.get(case_id, [])
    kml_str = FlightPathAnalyzer.export_kml(pts, flight_title=f"Flight Track - {case_id}")
    return Response(
        content=kml_str,
        media_type="application/vnd.google-earth.kml+xml",
        headers={"Content-Disposition": f'attachment; filename="{case_id}_flight.kml"'}
    )


@app.get("/api/cases/{case_id}/summary", response_model=FlightSummary)
def get_summary(case_id: str):
    pts = CASE_TELEMETRY.get(case_id, [])
    events = CASE_EVENTS.get(case_id, [])
    vios = CASE_VIOLATIONS.get(case_id, [])
    anoms = CASE_ANOMALIES.get(case_id, [])

    platform_name = "UNKNOWN"
    if CASE_EVIDENCE.get(case_id):
        platform_name = CASE_EVIDENCE[case_id][0].drone_platform or "UNKNOWN"

    gcs_res = CASE_GCS_DATA.get(case_id)
    op_loc = gcs_res.operator_locations[0] if (gcs_res and gcs_res.operator_locations) else None
    gcs_name = gcs_res.detected_gcs if (gcs_res and gcs_res.detected_gcs != "NONE") else None

    return FlightPathAnalyzer.calculate_summary(
        pts,
        platform_name=platform_name,
        events=events,
        events_count=len(events),
        violations_count=len(vios),
        anomalies_count=len(anoms),
        operator_location=op_loc,
        gcs_detected=gcs_name
    )


# --- GROUND CONTROL STATION (GCS) FORENSIC API ---

@app.get("/api/cases/{case_id}/gcs", response_model=GCSAnalysisResult)
def get_case_gcs_analysis(case_id: str):
    """
    Returns complete Ground Control Station forensic analysis for the case:
    detected GCS software, operator geolocations, planned mission waypoints,
    and planned vs. executed trajectory compliance metrics.
    """
    if case_id not in CASES_STORE:
        raise HTTPException(status_code=404, detail="Case not found.")

    if case_id not in CASE_GCS_DATA:
        return GCSAnalysisResult(
            detected_gcs="NONE",
            associated_fc="NONE",
            gcs_artifacts=[],
            operator_locations=[],
            mission_plans=[]
        )

    return CASE_GCS_DATA[case_id]


@app.get("/api/gcs/supported-stations")
def get_supported_ground_stations():
    """
    Returns catalog of all supported Ground Control Stations, compatible FCs,
    recognized file formats, and forensic capabilities.
    """
    return [
        {
            "gcs_name": "Mission Planner",
            "developer": "Michael Oborne / ArduPilot Community",
            "compatible_fcs": ["ArduPilot (ArduCopter, ArduPlane, ArduRover, Pixhawk, Cube)"],
            "supported_extensions": [".tlog", ".waypoints", ".plan", ".param", ".parm"],
            "forensic_capabilities": [
                "MAVLink 1.0 & 2.0 Downlink Telemetry Stream Decoding",
                "QGC WPL 110 Autonomous Mission Item Parsing",
                "GCS Vehicle Home / Operator Launch Coordinate Recovery",
                "Pre-Arm Check & Downlink STATUSTEXT Parsing",
                "Vehicle Parameter Dump Extraction"
            ]
        },
        {
            "gcs_name": "QGroundControl (QGC)",
            "developer": "Dronecode Project / Lorenz Meier",
            "compatible_fcs": ["PX4 Autopilot (Pixhawk, FMUv5/v6)", "ArduPilot"],
            "supported_extensions": [".plan", ".waypoints", ".tlog", ".csv"],
            "forensic_capabilities": [
                "QGC JSON Plan Parsing (Mission Items, Survey Grids)",
                "Geofence Inclusion & Exclusion Polygon Extraction",
                "Emergency Rally Point Decoding",
                "Planned Home Position Recovery",
                "MAVLink Telemetry Stream Analysis"
            ]
        },
        {
            "gcs_name": "DJI Pilot / DJI Pilot 2 (WPML)",
            "developer": "DJI Enterprise",
            "compatible_fcs": ["Matrice 300/350 RTK", "Mavic 3 Enterprise", "Inspire 3"],
            "supported_extensions": [".kmz", ".kml", ".txt", ".csv"],
            "forensic_capabilities": [
                "Waypoint Markup Language (WPML) 3D Trajectory Parsing",
                "Placemark Altitude & Waypoint Speed Extraction",
                "Camera & Sensor Trigger Action Reconstruction",
                "Remote Controller Pilot GPS Geolocation Recovery"
            ]
        },
        {
            "gcs_name": "DJI Ground Station Pro (GS Pro)",
            "developer": "DJI",
            "compatible_fcs": ["Phantom 4 RTK", "Matrice 200/210", "Mavic 2 Pro"],
            "supported_extensions": [".json", ".kml"],
            "forensic_capabilities": [
                "Grid Photogrammetry Survey Plan Extraction",
                "Waypoints Speed & Heading Sequence Decoding",
                "GS Pro Home Position & Boundary Recovery"
            ]
        },
        {
            "gcs_name": "DJI Fly / DJI GO 4",
            "developer": "DJI",
            "compatible_fcs": ["DJI Mini / Air / Mavic / Phantom Series"],
            "supported_extensions": [".txt", ".csv", ".dat"],
            "forensic_capabilities": [
                "Mobile Device FlightRecord OSD & Home Decoding",
                "Remote Controller Stick & Switch Input Reconstruction",
                "Operator Smartphone / Smart Controller Geolocation"
            ]
        },
        {
            "gcs_name": "iNav Configurator & Mission Planner / mwp",
            "developer": "iNav Flight / Cleanflight / stronnag (mwp)",
            "compatible_fcs": ["iNav / Betaflight (Autonomous Wings & Long-Range Quads)"],
            "supported_extensions": [".mission", ".mwp", ".xml", ".txt"],
            "forensic_capabilities": [
                "iNav Autonomous Navigation Mission Parsing (WAYPOINT, RTH, POSHOLD)",
                "MWP XML Waypoint Trajectory Decoding",
                "Configurator CLI Failsafe RTH & Nav Parameter Analysis"
            ]
        },
        {
            "gcs_name": "Parrot FreeFlight 6 / FlightPlan",
            "developer": "Parrot Drones SAS",
            "compatible_fcs": ["Parrot Anafi / Anafi USA / Bebop 2 / Disco"],
            "supported_extensions": [".mavlink", ".json", ".pud"],
            "forensic_capabilities": [
                "FreeFlight Autonomous FlightPlan Mission Extraction",
                "Parrot Skycontroller 3/4 Hardware Telemetry Recovery",
                "Operator Mobile Controller GPS Geolocation"
            ]
        }
    ]


# --- GEOFENCING CONFIGURATION, REAL-WORLD CATALOG & EVALUATION ---

@app.get("/api/geofence/catalog", response_model=List[GeofenceZone])
def get_geofence_catalog(
    category: Optional[str] = None,
    region: Optional[str] = None
):
    """
    Returns the master catalog of real-world restricted airspaces (airports, aerodromes,
    military airbases, government secretariats, nuclear/strategic sites, prisons).
    Filterable by category and region.
    """
    return get_catalog_filtered(category=category, city_region=region)


@app.get("/api/cases/{case_id}/geofence/zones", response_model=List[GeofenceZone])
def list_geofence_zones(case_id: str):
    if case_id not in CASES_STORE:
        raise HTTPException(status_code=404, detail="Case not found.")
    return CASE_GEOFENCE_ENGINES[case_id].zones


@app.post("/api/cases/{case_id}/geofence/zones")
def add_geofence_zone(case_id: str, req: AddZoneRequest, actor: str = "Investigator"):
    if case_id not in CASES_STORE:
        raise HTTPException(status_code=404, detail="Case not found.")

    engine = CASE_GEOFENCE_ENGINES[case_id]
    zone_id = f"ZONE-CUST-{len(engine.zones) + 1:03d}"

    zone = GeofenceZone(
        zone_id=zone_id,
        name=req.name,
        zone_type=req.zone_type,  # type: ignore
        coordinates=req.coordinates,
        center_lat=req.center_lat,
        center_lon=req.center_lon,
        radius_meters=req.radius_meters,
        max_altitude_m=req.max_altitude_m,
        description=req.description,
        category=req.category or "CUSTOM",
        zone_class=req.zone_class or "RED",
        authority=req.authority,
        city_region=req.city_region
    )

    engine.add_zone(zone)

    # Re-evaluate all telemetry against new zone
    violations = engine.evaluate_telemetry(CASE_TELEMETRY.get(case_id, []))
    CASE_VIOLATIONS[case_id] = violations

    coc_db.log_action(
        case_id=case_id,
        actor=actor,
        action="GEOFENCE_ZONE_CONFIGURED",
        details=f"Configured custom geofence '{req.name}' ({req.zone_type}). Current violations: {len(violations)}"
    )

    return {
        "zone": zone,
        "total_zones": len(engine.zones),
        "re_evaluated_violations": len(violations)
    }


@app.post("/api/cases/{case_id}/geofence/import-preset/{preset_id}")
def import_geofence_preset(case_id: str, preset_id: str, actor: str = "Investigator"):
    """Imports a real-world restricted airspace preset (e.g. Airport, Aerodrome, Government) into case."""
    if case_id not in CASES_STORE:
        raise HTTPException(status_code=404, detail="Case not found.")

    engine = CASE_GEOFENCE_ENGINES[case_id]
    zone = engine.import_preset(preset_id)
    if not zone:
        raise HTTPException(status_code=404, detail=f"Preset {preset_id} not found in restricted airspace catalog.")

    violations = engine.evaluate_telemetry(CASE_TELEMETRY.get(case_id, []))
    CASE_VIOLATIONS[case_id] = violations

    coc_db.log_action(
        case_id=case_id,
        actor=actor,
        action="RESTRICTED_AIRSPACE_IMPORTED",
        details=f"Imported real-world restricted airspace '{zone.name}' [{zone.category} - {zone.authority}]. Total breaches: {len(violations)}"
    )

    return {
        "status": "IMPORTED",
        "zone": zone,
        "total_zones": len(engine.zones),
        "violations_detected": len(violations)
    }


@app.post("/api/cases/{case_id}/geofence/load-all-presets")
def load_all_geofence_presets(case_id: str, actor: str = "Investigator"):
    """Bulk imports all real-world restricted airspace presets into the active case."""
    if case_id not in CASES_STORE:
        raise HTTPException(status_code=404, detail="Case not found.")

    engine = CASE_GEOFENCE_ENGINES[case_id]
    added_count = engine.load_all_presets()

    violations = engine.evaluate_telemetry(CASE_TELEMETRY.get(case_id, []))
    CASE_VIOLATIONS[case_id] = violations

    coc_db.log_action(
        case_id=case_id,
        actor=actor,
        action="ALL_RESTRICTED_AIRSPACES_LOADED",
        details=f"Bulk-imported {added_count} real-world restricted airspaces into case. Total active zones: {len(engine.zones)}. Violations: {len(violations)}"
    )

    return {
        "status": "ALL_PRESETS_LOADED",
        "added_count": added_count,
        "total_zones": len(engine.zones),
        "violations_detected": len(violations)
    }


@app.get("/api/cases/{case_id}/geofence/violations", response_model=List[GeofenceViolation])
def list_geofence_violations(case_id: str):
    return CASE_VIOLATIONS.get(case_id, [])


# --- TIMELINE & ANOMALIES ---

@app.get("/api/cases/{case_id}/timeline")
def get_timeline(case_id: str):
    events = CASE_EVENTS.get(case_id, [])
    vios = CASE_VIOLATIONS.get(case_id, [])
    anoms = CASE_ANOMALIES.get(case_id, [])
    return TimelineReconstructor.build_master_timeline(events, vios, anoms)


@app.get("/api/cases/{case_id}/anomalies", response_model=List[AnomalyReport])
def list_anomalies(case_id: str):
    return CASE_ANOMALIES.get(case_id, [])


# --- REPORTING EXPORTS ---

@app.get("/api/cases/{case_id}/report/html", response_class=HTMLResponse)
def get_html_report(case_id: str):
    if case_id not in CASES_STORE:
        raise HTTPException(status_code=404, detail="Case not found.")

    case = CASES_STORE[case_id]
    pts = CASE_TELEMETRY.get(case_id, [])
    events = CASE_EVENTS.get(case_id, [])
    vios = CASE_VIOLATIONS.get(case_id, [])
    anoms = CASE_ANOMALIES.get(case_id, [])
    ev_items = CASE_EVIDENCE.get(case_id, [])
    audit_logs = coc_db.get_entries(case_id)
    timeline = TimelineReconstructor.build_master_timeline(events, vios, anoms)

    platform_name = ev_items[0].drone_platform if ev_items else "UNKNOWN"
    gcs_res = CASE_GCS_DATA.get(case_id)
    op_loc = gcs_res.operator_locations[0] if (gcs_res and gcs_res.operator_locations) else None
    gcs_name = gcs_res.detected_gcs if (gcs_res and gcs_res.detected_gcs != "NONE") else None

    summary = FlightPathAnalyzer.calculate_summary(
        pts, platform_name=platform_name,
        events=events,
        events_count=len(events), violations_count=len(vios), anomalies_count=len(anoms),
        operator_location=op_loc,
        gcs_detected=gcs_name
    )

    media_items = CASE_MEDIA.get(case_id, [])
    html = ForensicReportGenerator.generate_html_report(
        case=case, summary=summary, evidence_items=ev_items,
        geofence_violations=vios, anomalies=anoms, timeline=timeline, audit_logs=audit_logs,
        gcs_analysis=gcs_res, media_items=media_items
    )
    return html


@app.get("/api/cases/{case_id}/report/json")
def get_json_report(case_id: str):
    if case_id not in CASES_STORE:
        raise HTTPException(status_code=404, detail="Case not found.")

    case = CASES_STORE[case_id]
    pts = CASE_TELEMETRY.get(case_id, [])
    events = CASE_EVENTS.get(case_id, [])
    vios = CASE_VIOLATIONS.get(case_id, [])
    anoms = CASE_ANOMALIES.get(case_id, [])
    ev_items = CASE_EVIDENCE.get(case_id, [])
    audit_logs = coc_db.get_entries(case_id)
    timeline = TimelineReconstructor.build_master_timeline(events, vios, anoms)

    platform_name = ev_items[0].drone_platform if ev_items else "UNKNOWN"
    gcs_res = CASE_GCS_DATA.get(case_id)
    op_loc = gcs_res.operator_locations[0] if (gcs_res and gcs_res.operator_locations) else None
    gcs_name = gcs_res.detected_gcs if (gcs_res and gcs_res.detected_gcs != "NONE") else None

    summary = FlightPathAnalyzer.calculate_summary(
        pts, platform_name=platform_name,
        events=events,
        events_count=len(events), violations_count=len(vios), anomalies_count=len(anoms),
        operator_location=op_loc,
        gcs_detected=gcs_name
    )

    media_items = CASE_MEDIA.get(case_id, [])
    json_str = ForensicReportGenerator.generate_json_export(
        case=case, summary=summary, evidence_items=ev_items,
        geofence_violations=vios, anomalies=anoms, timeline=timeline, audit_logs=audit_logs,
        gcs_analysis=gcs_res, media_items=media_items
    )
    return Response(content=json_str, media_type="application/json")


@app.get("/api/cases/{case_id}/report/dfxml")
def get_dfxml_report(case_id: str):
    if case_id not in CASES_STORE:
        raise HTTPException(status_code=404, detail="Case not found.")
    case = CASES_STORE[case_id]
    ev_items = CASE_EVIDENCE.get(case_id, [])
    media_items = CASE_MEDIA.get(case_id, [])
    dfxml = ForensicReportGenerator.generate_dfxml_export(case, ev_items, media_items=media_items)
    return Response(
        content=dfxml,
        media_type="application/xml",
        headers={"Content-Disposition": f'attachment; filename="{case_id}_dfxml.xml"'}
    )


# --- BENCHMARK DATASETS & VERIFICATION API ---

class RunBenchmarkRequest(BaseModel):
    benchmark_id: Optional[str] = None


@app.get("/api/benchmarks")
def api_list_benchmarks():
    """Lists all 6 registered forensic benchmark reference datasets."""
    from dft.benchmarks.registry import list_benchmarks
    benchmarks = list_benchmarks()
    return [
        {
            "id": b.id,
            "name": b.name,
            "short_title": b.short_title,
            "category": b.category.value,
            "citation": b.citation,
            "reference_url": b.reference_url,
            "source_organization": b.source_organization,
            "target_platforms": b.target_platforms,
            "evidence_types": b.evidence_types,
            "toolkit_layers": b.toolkit_layers,
            "evaluation_criteria_mapping": b.evaluation_criteria_mapping,
            "description": b.description,
            "forensic_challenges": b.forensic_challenges,
            "metrics": [
                {
                    "metric_id": m.metric_id,
                    "name": m.name,
                    "target_threshold": m.target_threshold,
                    "unit": m.unit,
                    "description": m.description
                }
                for m in b.metrics
            ],
            "sample_cases": [
                {
                    "case_id": sc.case_id,
                    "name": sc.name,
                    "platform": sc.platform,
                    "evidence_type": sc.evidence_type,
                    "description": sc.description,
                    "ground_truth_summary": sc.ground_truth_summary
                }
                for sc in b.sample_cases
            ]
        }
        for b in benchmarks
    ]


@app.get("/api/benchmarks/{benchmark_id}")
def api_get_benchmark(benchmark_id: str):
    """Retrieves detailed specification for a single forensic benchmark dataset."""
    from dft.benchmarks.registry import get_benchmark_by_id
    b = get_benchmark_by_id(benchmark_id)
    if not b:
        raise HTTPException(status_code=404, detail=f"Benchmark dataset '{benchmark_id}' not found.")
    return {
        "id": b.id,
        "name": b.name,
        "short_title": b.short_title,
        "category": b.category.value,
        "citation": b.citation,
        "reference_url": b.reference_url,
        "source_organization": b.source_organization,
        "target_platforms": b.target_platforms,
        "evidence_types": b.evidence_types,
        "toolkit_layers": b.toolkit_layers,
        "evaluation_criteria_mapping": b.evaluation_criteria_mapping,
        "description": b.description,
        "forensic_challenges": b.forensic_challenges,
        "metrics": [
            {
                "metric_id": m.metric_id,
                "name": m.name,
                "target_threshold": m.target_threshold,
                "unit": m.unit,
                "description": m.description
            }
            for m in b.metrics
        ],
        "sample_cases": [
            {
                "case_id": sc.case_id,
                "name": sc.name,
                "platform": sc.platform,
                "evidence_type": sc.evidence_type,
                "description": sc.description,
                "ground_truth_summary": sc.ground_truth_summary
            }
            for sc in b.sample_cases
        ]
    }


@app.post("/api/benchmarks/run")
def api_run_benchmark(req: Optional[RunBenchmarkRequest] = None):
    """Executes automated benchmark evaluation suite and returns scored results."""
    from dft.benchmarks.evaluator import BenchmarkEvaluator
    evaluator = BenchmarkEvaluator()

    if req and req.benchmark_id:
        single_res = evaluator.run_benchmark(req.benchmark_id)
        if not single_res:
            raise HTTPException(status_code=404, detail=f"Benchmark dataset '{req.benchmark_id}' not found.")
        return {
            "mode": "SINGLE_BENCHMARK",
            "benchmark_id": single_res.benchmark_id,
            "benchmark_name": single_res.benchmark_name,
            "short_title": single_res.short_title,
            "passed": single_res.passed,
            "score": single_res.score,
            "checks_run": single_res.checks_run,
            "checks_passed": single_res.checks_passed,
            "details": single_res.details
        }
    else:
        suite_res = evaluator.run_all()
        return {
            "mode": "FULL_SUITE",
            "total_benchmarks": suite_res.total_benchmarks,
            "benchmarks_passed": suite_res.benchmarks_passed,
            "overall_score": suite_res.overall_score,
            "all_passed": suite_res.all_passed,
            "summary": suite_res.summary,
            "results": [
                {
                    "benchmark_id": r.benchmark_id,
                    "benchmark_name": r.benchmark_name,
                    "short_title": r.short_title,
                    "category": r.category,
                    "passed": r.passed,
                    "score": r.score,
                    "checks_run": r.checks_run,
                    "checks_passed": r.checks_passed,
                    "details": r.details
                }
                for r in suite_res.results
            ]
        }


@app.post("/api/benchmarks/fetch-real-data")
def api_fetch_real_benchmark_data():
    """Downloads or verifies real reference benchmark datasets (VTO Labs, AirData UAV, PX4 ULog, Aerial Drone Photo)."""
    from dft.benchmarks.downloader import fetch_real_benchmark_data
    res = fetch_real_benchmark_data()
    return res


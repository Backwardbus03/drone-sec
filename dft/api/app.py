"""
FastAPI Server for Drone Forensic Toolkit (DFT).
REST API backend exposing cases, evidence ingestion, telemetry, geofencing, timeline, and reporting.
"""

from pathlib import Path
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from dft.core.models import (
    CaseMetadata, EvidenceItem, TelemetryPoint, FlightEvent,
    GeofenceZone, GeofenceViolation, AnomalyReport, FlightSummary, AuditLogEntry
)
from dft.core.hashing import compute_hashes
from dft.core.chain_of_custody import ChainOfCustodyManager
from dft.core.write_blocker import WriteBlockController
from dft.plugins.manager import PluginManager
from dft.analysis.geofence import GeofenceEngine
from dft.analysis.flight_path import FlightPathAnalyzer
from dft.analysis.timeline import TimelineReconstructor
from dft.analysis.anomaly import AnomalyDetector
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
CASE_TELEMETRY: Dict[str, List[TelemetryPoint]] = {}
CASE_EVENTS: Dict[str, List[FlightEvent]] = {}
CASE_GEOFENCE_ENGINES: Dict[str, GeofenceEngine] = {}
CASE_VIOLATIONS: Dict[str, List[GeofenceViolation]] = {}
CASE_ANOMALIES: Dict[str, List[AnomalyReport]] = {}
CASE_METADATA_EXTRA: Dict[str, Dict[str, Any]] = {}


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
    CASE_TELEMETRY[case_id] = []
    CASE_EVENTS[case_id] = []
    CASE_GEOFENCE_ENGINES[case_id] = GeofenceEngine()
    CASE_VIOLATIONS[case_id] = []
    CASE_ANOMALIES[case_id] = []
    CASE_METADATA_EXTRA[case_id] = {}

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
    return {
        "case": CASES_STORE[case_id],
        "evidence_count": len(CASE_EVIDENCE.get(case_id, [])),
        "telemetry_count": len(CASE_TELEMETRY.get(case_id, [])),
        "events_count": len(CASE_EVENTS.get(case_id, [])),
        "violations_count": len(CASE_VIOLATIONS.get(case_id, [])),
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

    return {
        "evidence_item": evidence,
        "platform_detected": platform_id,
        "telemetry_points_extracted": len(telemetry),
        "events_extracted": len(events),
        "violations_detected": len(violations),
        "anomalies_detected": len(anomalies)
    }


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

    return FlightPathAnalyzer.calculate_summary(
        pts,
        platform_name=platform_name,
        events=events,
        events_count=len(events),
        violations_count=len(vios),
        anomalies_count=len(anoms)
    )


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
    summary = FlightPathAnalyzer.calculate_summary(
        pts, platform_name=platform_name,
        events=events,
        events_count=len(events), violations_count=len(vios), anomalies_count=len(anoms)
    )

    html = ForensicReportGenerator.generate_html_report(
        case=case, summary=summary, evidence_items=ev_items,
        geofence_violations=vios, anomalies=anoms, timeline=timeline, audit_logs=audit_logs
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
    summary = FlightPathAnalyzer.calculate_summary(
        pts, platform_name=platform_name,
        events=events,
        events_count=len(events), violations_count=len(vios), anomalies_count=len(anoms)
    )

    json_str = ForensicReportGenerator.generate_json_export(
        case=case, summary=summary, evidence_items=ev_items,
        geofence_violations=vios, anomalies=anoms, timeline=timeline, audit_logs=audit_logs
    )
    return Response(content=json_str, media_type="application/json")


@app.get("/api/cases/{case_id}/report/dfxml")
def get_dfxml_report(case_id: str):
    if case_id not in CASES_STORE:
        raise HTTPException(status_code=404, detail="Case not found.")
    case = CASES_STORE[case_id]
    ev_items = CASE_EVIDENCE.get(case_id, [])
    dfxml = ForensicReportGenerator.generate_dfxml_export(case, ev_items)
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


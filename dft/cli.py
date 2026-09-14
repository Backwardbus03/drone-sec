import sys
import argparse
from pathlib import Path

# Add project root to sys.path for direct script execution
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dft.core.hashing import compute_hashes
from dft.core.chain_of_custody import ChainOfCustodyManager
from dft.core.write_blocker import WriteBlockController
from dft.plugins.manager import PluginManager
from dft.analysis.geofence import GeofenceEngine
from dft.analysis.flight_path import FlightPathAnalyzer
from dft.analysis.timeline import TimelineReconstructor
from dft.analysis.anomaly import AnomalyDetector
from dft.reporting.generator import ForensicReportGenerator
from dft.core.models import CaseMetadata, EvidenceItem


def main():
    parser = argparse.ArgumentParser(
        description="Drone Forensic Toolkit (DFT) — Autonomous UAV Investigation Engine"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: server
    server_parser = subparsers.add_parser("serve", help="Launch DFT FastAPI Web Console")
    server_parser.add_argument("--host", default="127.0.0.1", help="Bind address")
    server_parser.add_argument("--port", type=int, default=8000, help="Listening port")

    # Command: hash
    hash_parser = subparsers.add_parser("hash", help="Compute dual cryptographic hashes of a file")
    hash_parser.add_argument("file", help="Path to evidence file")

    # Command: parse
    parse_parser = subparsers.add_parser("parse", help="Parse and extract telemetry from drone evidence")
    parse_parser.add_argument("file", help="Path to flight log or media file")

    # Command: report
    rep_parser = subparsers.add_parser("report", help="Generate standalone ISO 27037 forensic report from log file")
    rep_parser.add_argument("file", help="Path to flight log file")
    rep_parser.add_argument("--out", default="forensic_report.html", help="Output HTML file path")
    rep_parser.add_argument("--examiner", default="Forensic Analyst", help="Examiner name")
    rep_parser.add_argument("--case", default="CLI-CASE-001", help="Case identifier")

    # Command: gcs
    gcs_parser = subparsers.add_parser("gcs", help="Inspect GCS telemetry, mission plans, operator locations, and waypoints")
    gcs_parser.add_argument("file", help="Path to GCS telemetry/mission plan file (.tlog, .plan, .waypoints, .kml, .json, .mission, etc.)")
    gcs_parser.add_argument("--flight-log", default=None, help="Optional flight log file to compare planned mission vs flown path")

    # Command: plugins
    subparsers.add_parser("plugins", help="List registered drone platform plugins")

    # Command: benchmark / benchmarks
    bench_parser = subparsers.add_parser("benchmark", aliases=["benchmarks"], help="Inspect reference forensic benchmark datasets and run validation suite")
    bench_parser.add_argument("--run", action="store_true", help="Execute automated benchmark validation suite")
    bench_parser.add_argument("--dataset", help="Specific benchmark ID to evaluate (e.g. ardupilot-flight-suite)")
    bench_parser.add_argument("--fetch-real-data", action="store_true", help="Download genuine real flight records, ULogs, and aerial photos from public research repositories into benchmarks/data/")

    args = parser.parse_args()

    if args.command == "serve":
        import uvicorn
        print(f"[*] Starting Drone Forensic Toolkit at http://{args.host}:{args.port}")
        print(f"[*] Investigation Console: http://{args.host}:{args.port}/dashboard")
        uvicorn.run("dft.api.app:app", host=args.host, port=args.port, reload=False)

    elif args.command == "hash":
        p = Path(args.file)
        if not p.exists():
            print(f"[!] File not found: {args.file}")
            sys.exit(1)
        wb = WriteBlockController.verify_read_only_status(p)
        manifest = compute_hashes(p)
        print(f"=== EVIDENCE HASH MANIFEST ===")
        print(f"File: {p.name} ({manifest.byte_count} bytes)")
        print(f"SHA-256 : {manifest.sha256}")
        print(f"SHA3-256: {manifest.sha3_256}")
        print(f"MD5     : {manifest.md5}")
        print(f"Write-Protected: {wb['canary_write_blocked']}")

    elif args.command == "parse":
        p = Path(args.file)
        mgr = PluginManager()
        platform_id, telemetry, events, meta = mgr.parse_evidence(p)
        print(f"=== PARSED EVIDENCE SUMMARY ===")
        print(f"Target: {p.name}")
        print(f"Platform Detected: {platform_id.upper()}")
        print(f"Telemetry Points : {len(telemetry)}")
        print(f"Discrete Events  : {len(events)}")

        geo_engine = GeofenceEngine()
        violations = geo_engine.evaluate_telemetry(telemetry)
        print(f"Geofence Breaches: {len(violations)}")

        anomalies = AnomalyDetector.inspect(telemetry, events)
        print(f"Anomalies Found  : {len(anomalies)}")

        summary = FlightPathAnalyzer.calculate_summary(
            telemetry, platform_name=platform_id,
            events=events,
            events_count=len(events), violations_count=len(violations), anomalies_count=len(anomalies)
        )
        print(f"Armed At         : {summary.arm_time_utc or 'N/A'}")
        print(f"Disarmed At      : {summary.disarm_time_utc or 'N/A'}")
        print(f"Total Distance   : {summary.total_distance_meters} m")
        print(f"Peak Altitude    : {summary.max_altitude_m} m")
        print(f"Max Speed        : {summary.max_speed_mps} m/s")
        if summary.gcs_detected:
            print(f"GCS Software     : {summary.gcs_detected}")
        if summary.operator_location:
            op = summary.operator_location
            print(f"Operator Location: {op.latitude:.6f}, {op.longitude:.6f} (Alt: {op.altitude_m}m, Source: {op.source})")

    elif args.command == "gcs":
        from dft.analysis.gcs import GCSAnalyzer
        from dft.core.models import OperatorLocation
        p = Path(args.file)
        if not p.exists():
            print(f"[!] File not found: {args.file}")
            sys.exit(1)

        gcs_software, fc_family = GCSAnalyzer.identify_gcs_format(p)
        print("================================================================================")
        print("         DRONE FORENSIC TOOLKIT — GROUND CONTROL STATION FORENSIC AUDIT         ")
        print("================================================================================")
        print(f"Evidence File        : {p.name} ({p.stat().st_size} bytes)")
        print(f"Format Detected      : {p.suffix.upper()} ({p.name})")
        print(f"GCS Software         : {gcs_software or 'Unknown GCS'}")
        print(f"Target FC Family     : {fc_family or 'Unknown FC'}")

        ext = p.suffix.lower()
        operator_loc = None
        plan = None
        tlog_points = []

        if ext == ".tlog":
            telemetry, events, operator_locations, meta = GCSAnalyzer.parse_mavlink_tlog(p)
            tlog_points = telemetry
            if operator_locations:
                operator_loc = operator_locations[0]
            print(f"Telemetry Packets    : {len(tlog_points)}")
            print(f"Events Extracted     : {len(events)}")
            print(f"Messages Decoded     : {meta.get('messages_decoded', 0)}")
        elif ext in (".waypoints", ".txt"):
            plan, _, _, operator_locations = GCSAnalyzer.parse_qgc_wpl(p)
            if operator_locations:
                operator_loc = operator_locations[0]
        elif ext == ".plan":
            plan, _, _, operator_locations, *_ = GCSAnalyzer.parse_qgc_plan(p)
            if operator_locations:
                operator_loc = operator_locations[0]
        elif ext in (".kml", ".kmz"):
            plan, _, _, operator_locations = GCSAnalyzer.parse_dji_wpml(p)
            if operator_locations:
                operator_loc = operator_locations[0]
        elif ext in (".mission", ".mwp"):
            plan, _, _, operator_locations = GCSAnalyzer.parse_inav_mission(p)
            if operator_locations:
                operator_loc = operator_locations[0]
        elif ext == ".mavlink":
            plan, _, _, operator_locations = GCSAnalyzer.parse_parrot_flightplan(p)
            if operator_locations:
                operator_loc = operator_locations[0]
        elif ext == ".json":
            try:
                plan, _, _, ops, *_ = GCSAnalyzer.parse_qgc_plan(p)
            except Exception:
                ops = []
            if not plan or not plan.waypoints:
                plan, _, _, ops = GCSAnalyzer.parse_dji_gspro(p)
            if not plan or not plan.waypoints:
                plan, _, _, ops = GCSAnalyzer.parse_inav_mission(p)
            if not plan or not plan.waypoints:
                plan, _, _, ops = GCSAnalyzer.parse_parrot_flightplan(p)
            if ops:
                operator_loc = ops[0]

        if not operator_loc and plan and plan.planned_home_lat and plan.planned_home_lon:
            operator_loc = OperatorLocation(
                source="PLANNED_HOME",
                latitude=plan.planned_home_lat,
                longitude=plan.planned_home_lon,
                altitude_m=plan.planned_home_alt_m or 0.0,
                description="Planned Home Position"
            )

        if operator_loc:
            print(f"\n[+] OPERATOR / GROUND STATION GEOLOCATION RECOVERED:")
            print(f"    Latitude         : {operator_loc.latitude:.6f}")
            print(f"    Longitude        : {operator_loc.longitude:.6f}")
            print(f"    Altitude         : {operator_loc.altitude_m or 0.0} m")
            print(f"    Timestamp (UTC)  : {operator_loc.timestamp_utc or 'N/A'}")
            print(f"    Confidence Source: {operator_loc.source}")
        else:
            print("\n[-] Operator geolocation not directly specified in file header.")

        if plan:
            print(f"\n[+] MISSION PLAN SPECIFICATIONS:")
            print(f"    Plan Name        : {plan.file_name}")
            print(f"    Total Waypoints  : {len(plan.waypoints)}")
            print(f"    Max Planned Alt  : {plan.planned_max_altitude_m} m")
            print(f"    Planned Distance : {plan.total_planned_distance_m} m")
            if plan.geofence_polygons:
                print(f"    Embedded Geofences: {len(plan.geofence_polygons)} polygon(s)")

            print("\n    WAYPOINT FLIGHT SCHEDULE:")
            print("    ----------------------------------------------------------------------------")
            print("    Seq | Action / Command      | Latitude   | Longitude  | Alt (m) | Spd (m/s) ")
            print("    ----------------------------------------------------------------------------")
            for wp in plan.waypoints:
                cmd = (wp.command or "WAYPOINT")[:21]
                spd = wp.speed_mps if wp.speed_mps is not None else 0.0
                print(f"    {wp.index:3d} | {cmd:21s} | {wp.latitude:10.6f} | {wp.longitude:10.6f} | {wp.altitude_m:7.1f} | {spd:9.1f}")
            print("    ----------------------------------------------------------------------------")

        telemetry_to_compare = []
        if args.flight_log:
            fl_path = Path(args.flight_log)
            if fl_path.exists():
                mgr = PluginManager()
                _, telemetry_to_compare, _, _ = mgr.parse_evidence(fl_path)
                print(f"\n[*] Loaded {len(telemetry_to_compare)} telemetry points from flight log: {fl_path.name}")
        elif tlog_points:
            telemetry_to_compare = tlog_points

        if plan and telemetry_to_compare:
            comparison = GCSAnalyzer.compare_mission_trajectory(plan, telemetry_to_compare)
            print("\n[+] AUTONOMOUS MISSION ADHERENCE & TRAJECTORY COMPLIANCE:")
            print(f"    Adherence Score  : {comparison['compliance_score_pct']}%")
            print(f"    Waypoints Reached: {comparison['waypoints_reached']} / {comparison['waypoints_total']}")
            print(f"    Mean Deviation   : {comparison['mean_deviation_meters']} m")
            print(f"    Max Deviation    : {comparison['max_deviation_meters']} m")
            if comparison.get('mission_interrupted'):
                print(f"    [!] MISSION INTERRUPTION DETECTED: Abandoned midway through planned route")

        print("================================================================================")

    elif args.command == "report":
        p = Path(args.file)
        mgr = PluginManager()
        platform_id, telemetry, events, meta = mgr.parse_evidence(p)
        manifest = compute_hashes(p)
        geo_engine = GeofenceEngine()
        violations = geo_engine.evaluate_telemetry(telemetry)
        anomalies = AnomalyDetector.inspect(telemetry, events)
        timeline = TimelineReconstructor.build_master_timeline(events, violations, anomalies)
        summary = FlightPathAnalyzer.calculate_summary(
            telemetry, platform_name=platform_id,
            events=events,
            events_count=len(events), violations_count=len(violations), anomalies_count=len(anomalies)
        )

        from dft.analysis.gcs import GCSAnalyzer
        from dft.core.models import GCSAnalysisResult
        gcs_software, fc_family = GCSAnalyzer.identify_gcs_format(p)
        gcs_res = None
        if gcs_software:
            plan = None
            ops = []
            ext = p.suffix.lower()
            if ext == ".plan":
                plan, _, _, ops = GCSAnalyzer.parse_qgc_plan(p)
            elif ext in (".waypoints", ".txt"):
                plan, _, _, ops = GCSAnalyzer.parse_qgc_wpl(p)
            elif ext in (".kml", ".kmz"):
                plan, _, _, ops = GCSAnalyzer.parse_dji_wpml(p)
            elif ext in (".mission", ".mwp"):
                plan, _, _, ops = GCSAnalyzer.parse_inav_mission(p)
            elif ext == ".mavlink":
                plan, _, _, ops = GCSAnalyzer.parse_parrot_flightplan(p)

            comp = None
            if plan and telemetry:
                comp = GCSAnalyzer.compare_mission_trajectory(plan, telemetry)

            gcs_res = GCSAnalysisResult(
                detected_gcs=gcs_software,
                associated_fc=fc_family or "General UAV",
                gcs_artifacts=[p.name],
                operator_locations=ops if ops else ([summary.operator_location] if summary.operator_location else []),
                mission_plans=[plan] if plan else [],
                mission_comparison=comp
            )

        case = CaseMetadata(
            case_id=args.case,
            case_name=f"Automated Examination of {p.name}",
            investigator_name=args.examiner,
            agency_name="Drone Forensics Command"
        )

        ev_item = EvidenceItem(
            item_id="EV-001",
            case_id=args.case,
            file_name=p.name,
            source_path=str(p.resolve()),
            file_size_bytes=manifest.byte_count,
            hashes=manifest,
            acquisition_type="LOGICAL_EXTRACT",
            drone_platform=platform_id
        )

        coc = ChainOfCustodyManager(Path("forensic_cases_vault/temp_audit.sqlite"))
        coc_entry = coc.log_action(args.case, args.examiner, "REPORT_GENERATED", f"Generated standalone examination report for {p.name}")

        html = ForensicReportGenerator.generate_html_report(
            case=case, summary=summary, evidence_items=[ev_item],
            geofence_violations=violations, anomalies=anomalies, timeline=timeline, audit_logs=[coc_entry],
            gcs_analysis=gcs_res
        )

        out_path = Path(args.out)
        out_path.write_text(html, encoding="utf-8")
        print(f"[+] Forensic Report successfully generated: {out_path.resolve()}")

    elif args.command == "plugins":
        mgr = PluginManager()
        print("=== REGISTERED DRONE FORENSIC PLUGINS ===")
        for pl in mgr.list_plugins():
            print(f"- {pl['display_name']} [ID: {pl['platform_id']}]")
            print(f"  Extensions: {', '.join(pl['supported_extensions'])}")

    elif args.command in ("benchmark", "benchmarks"):
        from dft.benchmarks.registry import BENCHMARK_REGISTRY, list_benchmarks, get_benchmark_by_id
        from dft.benchmarks.evaluator import BenchmarkEvaluator

        if getattr(args, "fetch_real_data", False):
            from dft.benchmarks.downloader import fetch_real_benchmark_data
            print("[*] Fetching genuine benchmark files from open-access UAV forensic repositories...")
            dl_res = fetch_real_benchmark_data()
            print(f"[+] Download Status: {dl_res['status']}")
            print(f"    Saved to: {dl_res['destination_directory']}")
            for f in dl_res['files']:
                cached_tag = "(cached)" if f.get('cached') else "(downloaded)"
                print(f"    - {f['file_name']} [{f['size_bytes']} bytes] {cached_tag}")
                print(f"      {f['description']}")
            if dl_res['errors']:
                print(f"[!] Errors encountered: {len(dl_res['errors'])}")
                for err in dl_res['errors']:
                    print(f"    - {err['key']}: {err['error']}")
            sys.exit(0)

        if args.run:
            evaluator = BenchmarkEvaluator()
            if args.dataset:
                b_res = evaluator.run_benchmark(args.dataset)
                if not b_res:
                    print(f"[!] Benchmark dataset '{args.dataset}' not found. Available:")
                    for b in list_benchmarks():
                        print(f"    - {b.id} ({b.short_title})")
                    sys.exit(1)
                print(f"=== BENCHMARK EVALUATION: {b_res.short_title.upper()} ===")
                print(f"Status: {'PASSED [100%]' if b_res.passed else 'FAILED'}")
                print(f"Score : {b_res.score}% ({b_res.checks_passed}/{b_res.checks_run} checks passed)")
                for chk in b_res.details:
                    symbol = "[+]" if chk["passed"] else "[X]"
                    print(f"  {symbol} {chk['check']}")
                    print(f"      {chk['detail']}")
            else:
                suite_res = evaluator.run_all()
                print("================================================================================")
                print("           DRONE FORENSIC TOOLKIT — BENCHMARK EVALUATION SUITE                  ")
                print("   ISO/IEC 27037:2012 (Preservation) & ISO/IEC 27042:2015 (Analysis/Reporting)  ")
                print("================================================================================")
                print(f"Overall Result : {'ALL SUITES PASSED' if suite_res.all_passed else 'SOME SUITES FAILED'}")
                print(f"Suites Passed  : {suite_res.benchmarks_passed} / {suite_res.total_benchmarks}")
                print(f"Composite Score: {suite_res.overall_score}%\n")

                for b_res in suite_res.results:
                    status_str = "PASS" if b_res.passed else "FAIL"
                    print(f"[{status_str}] {b_res.short_title} ({b_res.score}%)")
                    for chk in b_res.details:
                        s = "  +" if chk["passed"] else "  X"
                        print(f"  {s} {chk['check']}")

                print("================================================================================")
                print(f"[+] {suite_res.summary}")
        else:
            print("================================================================================")
            print("        REFERENCE FORENSIC BENCHMARK DATASETS (OBJECTIVE 1 EVALUATION)          ")
            print("================================================================================")
            for b in list_benchmarks():
                print(f"\n* [{b.id}] {b.name}")
                print(f"  Short Title: {b.short_title}")
                print(f"  Category   : {b.category.value}")
                print(f"  Citation   : {b.citation}")
                print(f"  Reference  : {b.reference_url}")
                print(f"  Platforms  : {', '.join(b.target_platforms)}")
                print(f"  Evidence   : {', '.join(b.evidence_types[:3])}...")
                print(f"  Layers     : {', '.join(b.toolkit_layers)}")
                print(f"  Evaluation : {b.evaluation_criteria_mapping}")
            print("\nRun validation with: python dft/cli.py benchmark --run")
            print("Run specific suite:  python dft/cli.py benchmark --run --dataset <id>")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()

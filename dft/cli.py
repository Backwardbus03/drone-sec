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

    # Command: plugins
    subparsers.add_parser("plugins", help="List registered drone platform plugins")

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
            geofence_violations=violations, anomalies=anomalies, timeline=timeline, audit_logs=[coc_entry]
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

    else:
        parser.print_help()


if __name__ == "__main__":
    main()

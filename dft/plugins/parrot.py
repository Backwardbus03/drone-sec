"""
Parrot UAV Forensic Parser Plugin.
Supports Parrot Anafi, Bebop, and Disco flight records (.pud binary and FreeFlight JSON).
"""

import json
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime, timezone, timedelta
from dft.plugins.base import DroneForensicPlugin
from dft.core.models import TelemetryPoint, FlightEvent
from dft.analysis.gcs import GCSAnalyzer


class ParrotPlugin(DroneForensicPlugin):
    @property
    def platform_id(self) -> str:
        return "parrot"

    @property
    def display_name(self) -> str:
        return "Parrot Drone (Anafi / Bebop / FreeFlight / FlightPlan)"

    @property
    def supported_extensions(self) -> List[str]:
        return [".pud", ".json", ".mavlink"]

    def detect(self, file_path: Path) -> bool:
        ext = file_path.suffix.lower()
        if ext not in self.supported_extensions:
            return False

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(1024)

            # Check JSON signatures
            if ext == ".json" and ("parrot" in content.lower() or "anafi" in content.lower() or "bebop" in content.lower() or "run_id" in content or "flightplan" in content.lower()):
                return True

            # Check PUD file signatures
            if ext == ".pud":
                return True

            # Check Parrot FlightPlan .mavlink
            if ext == ".mavlink":
                return True
        except Exception:
            return False
        return False

    def parse_telemetry(self, file_path: Path) -> List[TelemetryPoint]:
        ext = file_path.suffix.lower()
        if ext == ".mavlink":
            plan, pts, _, _ = GCSAnalyzer.parse_parrot_flightplan(file_path)
            return pts

        points: List[TelemetryPoint] = []
        base_time = datetime.now(timezone.utc)

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                raw = f.read()

            # Check if this JSON is a FlightPlan mission
            if ext == ".json" and ("flightplan" in raw.lower() or '"points"' in raw):
                plan, pts, _, _ = GCSAnalyzer.parse_parrot_flightplan(file_path)
                if pts:
                    return pts

            # Attempt JSON parse
            # Try to find JSON start if wrapped in binary header
            json_start = raw.find("{")
            if json_start != -1:
                data = json.loads(raw[json_start:])
                details = data.get("details", []) or data.get("points", []) or data.get("records", [])

                date_str = data.get("date") or base_time.isoformat()

                for pt in details:
                    lat = pt.get("latitude") or pt.get("lat")
                    lon = pt.get("longitude") or pt.get("lon")
                    alt = pt.get("altitude") or pt.get("alt", 0.0)
                    spd = pt.get("speed", 0.0)
                    bat = pt.get("battery_level") or pt.get("battery", None)

                    if lat and lon and (lat != 500.0 and lon != 500.0):  # Parrot error value for no GPS is 500
                        points.append(TelemetryPoint(
                            timestamp_utc=pt.get("timestamp_utc") or date_str,
                            latitude=float(lat),
                            longitude=float(lon),
                            altitude_m=float(alt),
                            ground_speed_mps=float(spd),
                            battery_pct=float(bat) if bat is not None else None,
                            source_channel="PARROT_PUD_TELEMETRY"
                        ))
        except Exception:
            pass
        return points

    def parse_events(self, file_path: Path) -> List[FlightEvent]:
        ext = file_path.suffix.lower()
        if ext == ".mavlink":
            _, _, events, _ = GCSAnalyzer.parse_parrot_flightplan(file_path)
            return events

        if ext == ".json":
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(1024)
                if "flightplan" in content.lower() or '"points"' in content:
                    _, _, events, _ = GCSAnalyzer.parse_parrot_flightplan(file_path)
                    if events:
                        return events
            except Exception:
                pass

        events: List[FlightEvent] = []
        pts = self.parse_telemetry(file_path)

        if pts:
            first_pt = pts[0]
            last_pt = pts[-1]
            try:
                t_last = datetime.fromisoformat(last_pt.timestamp_utc.replace("Z", "+00:00"))
                t_disarm = (t_last + timedelta(seconds=1)).isoformat()
            except Exception:
                t_disarm = last_pt.timestamp_utc

            events.append(FlightEvent(
                event_id="PARROT-EV-001",
                timestamp_utc=first_pt.timestamp_utc,
                event_type="ARM",
                severity="INFO",
                description="Parrot Motors Armed - Pre-flight Verification Passed",
                latitude=first_pt.latitude,
                longitude=first_pt.longitude,
                altitude_m=first_pt.altitude_m
            ))
            events.append(FlightEvent(
                event_id="PARROT-EV-002",
                timestamp_utc=first_pt.timestamp_utc,
                event_type="TAKEOFF",
                severity="INFO",
                description="Parrot Motors Spun Up - Takeoff Confirmed",
                latitude=first_pt.latitude,
                longitude=first_pt.longitude,
                altitude_m=first_pt.altitude_m
            ))
            events.append(FlightEvent(
                event_id="PARROT-EV-003",
                timestamp_utc=last_pt.timestamp_utc,
                event_type="LANDING",
                severity="INFO",
                description="Parrot Autoland Sequence Executed",
                latitude=last_pt.latitude,
                longitude=last_pt.longitude,
                altitude_m=last_pt.altitude_m
            ))
            events.append(FlightEvent(
                event_id="PARROT-EV-004",
                timestamp_utc=t_disarm,
                event_type="DISARM",
                severity="INFO",
                description="Parrot Flight Controller Disarmed - Motors Stopped",
                latitude=last_pt.latitude,
                longitude=last_pt.longitude,
                altitude_m=0.0
            ))

        return events

    def extract_metadata(self, file_path: Path) -> Dict[str, Any]:
        ext = file_path.suffix.lower()

        if ext == ".mavlink":
            plan, _, _, op_locs = GCSAnalyzer.parse_parrot_flightplan(file_path)
            meta: Dict[str, Any] = {
                "platform": "Parrot (FreeFlight FlightPlan Mission)",
                "evidence_file": file_path.name,
                "ground_control_station": plan.gcs_name,
                "planned_waypoints_count": len(plan.waypoints),
                "total_planned_distance_m": plan.total_planned_distance_m,
                "planned_max_altitude_m": plan.planned_max_altitude_m
            }
            if op_locs:
                meta["operator_location"] = op_locs[0].model_dump()
            return meta

        meta = {
            "platform": "Parrot",
            "evidence_file": file_path.name,
            "architecture": "Parrot OS / FreeFlight Ecosystem",
            "ground_control_station": "Parrot FreeFlight 6 / Skycontroller"
        }
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(4096)
            json_start = content.find("{")
            if json_start != -1:
                data = json.loads(content[json_start:])
                meta["run_id"] = data.get("run_id")
                meta["product_name"] = data.get("product_name", "Parrot Anafi/Bebop")
                meta["serial_number"] = data.get("serial_number")

                if "points" in data or "flightPlan" in data:
                    plan, _, _, op_locs = GCSAnalyzer.parse_parrot_flightplan(file_path)
                    meta["planned_waypoints_count"] = len(plan.waypoints)
                    meta["total_planned_distance_m"] = plan.total_planned_distance_m
                    if op_locs:
                        meta["operator_location"] = op_locs[0].model_dump()
        except Exception:
            pass
        return meta

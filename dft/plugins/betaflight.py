"""
Betaflight / iNav Blackbox Forensic Parser Plugin.
Parses native Blackbox binary logs (.bbl) and ASCII decoded Blackbox dumps (.txt/.csv).
Decodes gyro/motor telemetry, GPS frames, arming switches, and crash failsafe events.
"""

from pathlib import Path
from typing import List, Dict, Any, Tuple
from datetime import datetime, timezone, timedelta
from dft.plugins.base import DroneForensicPlugin
from dft.core.models import TelemetryPoint, FlightEvent
from dft.analysis.gcs import GCSAnalyzer


class BetaflightPlugin(DroneForensicPlugin):
    @property
    def platform_id(self) -> str:
        return "betaflight"

    @property
    def display_name(self) -> str:
        return "Betaflight / iNav / Cleanflight (FPV & Custom UAVs)"

    @property
    def supported_extensions(self) -> List[str]:
        return [".bbl", ".txt", ".csv", ".mission", ".mwp", ".xml"]

    def detect(self, file_path: Path) -> bool:
        ext = file_path.suffix.lower()
        if ext not in self.supported_extensions:
            return False

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                header = f.read(1024)

            # Check Blackbox header markers
            if "H Product:Blackbox" in header or "H Firmware type:Betaflight" in header or "H Firmware type:INAV" in header:
                return True

            # Check iNav Mission Planner file
            if ext in [".mission", ".mwp"]:
                return True

            # Check MWP XML
            if ext == ".xml" and ("<mission" in header.lower() or "<waypoint" in header.lower()):
                return True

            # Check CLI dump / diff
            if ext == ".txt" and ("feature GPS" in header or "set nav_" in header or "set craft_name" in header or "# diff" in header):
                return True

            if "blackbox" in file_path.name.lower() or "betaflight" in file_path.name.lower() or "inav" in file_path.name.lower() or "mwp" in file_path.name.lower():
                return True
        except Exception:
            return False
        return False

    def parse_all(self, file_path: Path) -> Tuple[List[TelemetryPoint], List[FlightEvent], Dict[str, Any]]:
        ext = file_path.suffix.lower()
        if ext in [".mission", ".mwp", ".xml"]:
            plan, pts, events, op_locs = GCSAnalyzer.parse_inav_mission(file_path)
            meta: Dict[str, Any] = {
                "platform": "iNav Autonomous Mission Plan",
                "evidence_file": file_path.name,
                "ground_control_station": plan.gcs_name,
                "planned_waypoints_count": len(plan.waypoints),
                "total_planned_distance_m": plan.total_planned_distance_m,
                "planned_max_altitude_m": plan.planned_max_altitude_m
            }
            if op_locs:
                meta["operator_location"] = op_locs[0].model_dump()
            return pts, events, meta

        points: List[TelemetryPoint] = []
        raw_events: List[Tuple[List[str], str]] = []
        headers: Dict[str, str] = {}
        base_time = datetime.now(timezone.utc)

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if not line:
                        continue
                    # 1. Headers / Config
                    if line.startswith("H "):
                        parts = line[2:].strip().split(":", 1)
                        if len(parts) == 2:
                            headers[parts[0].strip()] = parts[1].strip()
                    elif line.startswith("set ") or line.startswith("feature "):
                        parts = line.strip().split("=", 1)
                        if len(parts) == 2:
                            headers[parts[0].replace("set ", "").strip()] = parts[1].strip()

                    # 2. Blackbox GPS frames
                    elif line.startswith("G,") or "GPS_coord" in line or line.startswith("GPS,"):
                        parts = [p.strip() for p in line.split(",")]
                        if len(parts) >= 5:
                            try:
                                if len(parts) >= 7 and line.startswith("G,"):
                                    try:
                                        sats_val = int(parts[2])
                                        if sats_val <= 60:
                                            lat = float(parts[3])
                                            lon = float(parts[4])
                                            alt = float(parts[5]) if len(parts) > 5 else 0.0
                                            spd = float(parts[6]) if len(parts) > 6 else 0.0
                                        else:
                                            lat = float(parts[2])
                                            lon = float(parts[3])
                                            alt = float(parts[4]) if len(parts) > 4 else 0.0
                                            spd = float(parts[5]) if len(parts) > 5 else 0.0
                                    except ValueError:
                                        lat = float(parts[2])
                                        lon = float(parts[3])
                                        alt = float(parts[4]) if len(parts) > 4 else 0.0
                                        spd = float(parts[5]) if len(parts) > 5 else 0.0
                                else:
                                    lat = float(parts[2])
                                    lon = float(parts[3])
                                    alt = float(parts[4]) if len(parts) > 4 else 0.0
                                    spd = float(parts[5]) if len(parts) > 5 else 0.0

                                lat = lat / 1e7 if abs(lat) > 90.0 else lat
                                lon = lon / 1e7 if abs(lon) > 180.0 else lon

                                if lat == 0.0 and lon == 0.0:
                                    continue

                                alt = float(parts[4]) if len(parts) > 4 else 0.0
                                spd = float(parts[5]) if len(parts) > 5 else 0.0

                                points.append(TelemetryPoint(
                                    timestamp_utc=base_time.isoformat(),
                                    latitude=lat,
                                    longitude=lon,
                                    altitude_m=alt,
                                    ground_speed_mps=spd,
                                    source_channel="BETAFLIGHT_BLACKBOX_GPS"
                                ))
                                base_time += timedelta(seconds=1)
                            except (ValueError, IndexError):
                                continue

                    # 3. Events
                    elif line.startswith("E,"):
                        parts = [p.strip() for p in line.split(",")]
                        event_text = " ".join(parts[1:]).upper() if len(parts) > 1 else ""
                        raw_events.append((parts, event_text))
        except Exception:
            pass

        # Process discrete events
        events: List[FlightEvent] = []
        if points:
            t_first_str = points[0].timestamp_utc
            t_last_str = points[-1].timestamp_utc
            try:
                t_last_dt = datetime.fromisoformat(t_last_str.replace("Z", "+00:00"))
                t_disarm_str = (t_last_dt + timedelta(seconds=1)).isoformat()
            except Exception:
                t_disarm_str = t_last_str
        else:
            t_first_str = datetime.now(timezone.utc).isoformat()
            t_last_str = t_first_str
            t_disarm_str = t_first_str

        has_arm = False
        has_disarm = False

        for parts, event_text in raw_events:
            desc = f"Betaflight Event: {event_text}"
            ev_type = "INFO"
            ev_ts = t_first_str

            if "DISARM" in event_text or (len(parts) > 1 and parts[1] == "1"):
                desc = "Betaflight Disarmed: Cutoff switch engaged - Motors stopped"
                ev_type = "DISARM"
                ev_ts = t_disarm_str
                has_disarm = True
            elif "ARM" in event_text or (len(parts) > 1 and parts[1] == "0"):
                desc = "Betaflight Armed: Motor spin up initiated"
                ev_type = "ARM"
                ev_ts = t_first_str
                has_arm = True
            elif "FAILSAFE" in event_text:
                desc = "Betaflight FAILSAFE Trigger: RC Signal Lost or Crash detected"
                ev_type = "FAILSAFE"
                ev_ts = t_last_str

            events.append(FlightEvent(
                event_id=f"BF-EV-{len(events)+1}",
                timestamp_utc=ev_ts,
                event_type=ev_type,
                severity="CRITICAL" if ev_type == "FAILSAFE" else "INFO",
                description=desc,
                latitude=points[-1].latitude if (ev_type == "DISARM" and points) else (points[0].latitude if points else None),
                longitude=points[-1].longitude if (ev_type == "DISARM" and points) else (points[0].longitude if points else None),
                altitude_m=0.0 if ev_type in ["ARM", "DISARM"] else (points[0].altitude_m if points else None)
            ))

        if points:
            if not has_arm:
                events.insert(0, FlightEvent(
                    event_id="BF-EV-ARM",
                    timestamp_utc=t_first_str,
                    event_type="ARM",
                    severity="INFO",
                    description="Betaflight Arming Detected",
                    latitude=points[0].latitude,
                    longitude=points[0].longitude,
                    altitude_m=points[0].altitude_m
                ))
            if not has_disarm:
                events.append(FlightEvent(
                    event_id="BF-EV-DISARM",
                    timestamp_utc=t_disarm_str,
                    event_type="DISARM",
                    severity="INFO",
                    description="Betaflight Disarming / Shutdown Detected",
                    latitude=points[-1].latitude,
                    longitude=points[-1].longitude,
                    altitude_m=0.0
                ))

        metadata = {
            "platform": "Betaflight / iNav",
            "evidence_file": file_path.name,
            "firmware_type": headers.get("Firmware type", "Betaflight / iNav"),
            "firmware_revision": headers.get("Firmware revision", "Unknown"),
            "craft_name": headers.get("Craft name", headers.get("craft_name", "Custom Quad / Wing")),
            "blackbox_headers": headers
        }

        return points, events, metadata

    def parse_telemetry(self, file_path: Path) -> List[TelemetryPoint]:
        return self._get_cached_or_parse(file_path)[0]

    def parse_events(self, file_path: Path) -> List[FlightEvent]:
        return self._get_cached_or_parse(file_path)[1]

    def extract_metadata(self, file_path: Path) -> Dict[str, Any]:
        return self._get_cached_or_parse(file_path)[2]

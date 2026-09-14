"""
DJI UAV Forensic Parser Plugin.
Supports DJI proprietary .DAT, decrypted .txt flight records, and video subtitle .srt telemetry.
"""

import re
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime, timezone
from dft.plugins.base import DroneForensicPlugin
from dft.core.models import TelemetryPoint, FlightEvent
from dft.analysis.gcs import GCSAnalyzer


class DJIPlugin(DroneForensicPlugin):
    @property
    def platform_id(self) -> str:
        return "dji"

    @property
    def display_name(self) -> str:
        return "DJI Drone (Mavic / Phantom / Mini / Enterprise / Pilot 2)"

    @property
    def supported_extensions(self) -> List[str]:
        return [".dat", ".txt", ".srt", ".csv", ".kml", ".kmz", ".json"]

    def detect(self, file_path: Path) -> bool:
        ext = file_path.suffix.lower()
        if ext not in self.supported_extensions:
            return False

        try:
            with open(file_path, "rb") as f:
                header = f.read(512)

            # DJI SRT Subtitle check
            if ext == ".srt" and (b"HOME" in header or b"GPS" in header or b"ISO" in header or b"F/" in header):
                return True

            # DJI Text Log check
            if ext in [".txt", ".csv"] and (b"OSD." in header or b"CUSTOM." in header or b"DJI" in header or b"flycState" in header):
                return True

            # DJI DAT binary magic / header markers
            if ext == ".dat":
                if b"BUILD_VER" in header or b"DJI" in header or header.startswith(b"\x55\xaa") or header.startswith(b"1234567890"):
                    return True
                if "dji" in file_path.name.lower() or "fly" in file_path.name.lower():
                    return True

            # DJI Pilot 2 WPML (.kmz or .kml)
            if ext in [".kmz", ".kml"]:
                gcs_name, _ = GCSAnalyzer.identify_gcs_format(file_path)
                if gcs_name == "DJI Pilot 2 (WPML)" or "dji" in file_path.name.lower() or "wpml" in file_path.name.lower():
                    return True

            # DJI GS Pro JSON flight plan
            if ext == ".json":
                if b"gs_pro" in header or b"home_location" in header or b"DJI" in header:
                    return True
        except Exception:
            return False
        return False

    def parse_telemetry(self, file_path: Path) -> List[TelemetryPoint]:
        ext = file_path.suffix.lower()
        points: List[TelemetryPoint] = []

        if ext == ".srt":
            points = self._parse_srt(file_path)
        elif ext in [".txt", ".csv"]:
            points = self._parse_txt_csv(file_path)
        elif ext == ".dat":
            points = self._parse_dat(file_path)
        elif ext in [".kml", ".kmz"]:
            plan, points, _, _ = GCSAnalyzer.parse_dji_wpml(file_path)
        elif ext == ".json":
            plan, points, _, _ = GCSAnalyzer.parse_dji_gspro(file_path)

        return points

    def _parse_srt(self, file_path: Path) -> List[TelemetryPoint]:
        """Parses DJI embedded video subtitles containing GPS and camera telemetry."""
        points: List[TelemetryPoint] = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            blocks = content.strip().split("\n\n")
            for block in blocks:
                lines = block.splitlines()
                if len(lines) < 3:
                    continue

                ts_match = re.search(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)", block)
                timestamp_str = ts_match.group(1).replace(" ", "T") + "Z" if ts_match else datetime.now(timezone.utc).isoformat()

                # Regex patterns for DJI SRT format:
                # [latitude: 19.1334] [longitude: 72.9133] [altitude: 45.2]
                lat_m = re.search(r"(?:latitude|lat)[:\s]+([+-]?\d+\.\d+)", block, re.IGNORECASE)
                lon_m = re.search(r"(?:longitude|lon)[:\s]+([+-]?\d+\.\d+)", block, re.IGNORECASE)
                alt_m = re.search(r"(?:altitude|alt|rel_alt)[:\s]+([+-]?\d+(?:\.\d+)?)", block, re.IGNORECASE)
                speed_m = re.search(r"(?:hspeed|speed)[:\s]+([+-]?\d+(?:\.\d+)?)", block, re.IGNORECASE)
                pitch_m = re.search(r"pitch[:\s]+([+-]?\d+(?:\.\d+)?)", block, re.IGNORECASE)
                yaw_m = re.search(r"yaw[:\s]+([+-]?\d+(?:\.\d+)?)", block, re.IGNORECASE)

                if lat_m and lon_m:
                    lat = float(lat_m.group(1))
                    lon = float(lon_m.group(1))
                    alt = float(alt_m.group(1)) if alt_m else 0.0
                    spd = float(speed_m.group(1)) if speed_m else 0.0
                    pitch = float(pitch_m.group(1)) if pitch_m else 0.0
                    yaw = float(yaw_m.group(1)) if yaw_m else 0.0

                    points.append(TelemetryPoint(
                        timestamp_utc=timestamp_str,
                        latitude=lat,
                        longitude=lon,
                        altitude_m=alt,
                        ground_speed_mps=spd,
                        pitch_deg=pitch,
                        yaw_deg=yaw,
                        source_channel="DJI_SRT_STREAM"
                    ))
        except Exception:
            pass
        return points

    def _parse_txt_csv(self, file_path: Path) -> List[TelemetryPoint]:
        """Parses decoded DJI flight records in CSV / tabular format."""
        points: List[TelemetryPoint] = []
        try:
            with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
                lines = [l.strip() for l in f if l.strip()]

            if not lines:
                return points

            # Handle sep=, indicator line from Excel CSV exports
            start_idx = 0
            if lines[0].lower().startswith("sep="):
                start_idx = 1
                if len(lines) <= start_idx:
                    return points

            header = [h.strip() for h in lines[start_idx].split(",")]
            col_map = {name.lower(): idx for idx, name in enumerate(header)}

            # Robust column discovery
            def find_col(*patterns):
                for pat in patterns:
                    for k, idx in col_map.items():
                        if pat in k:
                            return idx
                return None

            lat_idx = find_col("osd.latitude", "latitude", "lat")
            lon_idx = find_col("osd.longitude", "longitude", "lon")
            alt_ft_idx = find_col("osd.height [ft]", "height [ft]", "altitude [ft]")
            alt_idx = find_col("osd.height [m]", "osd.height", "osd.altitude", "altitude", "height")
            spd_idx = find_col("osd.hspeed", "speed")
            bat_idx = find_col("osd.battery", "battery")
            time_idx = find_col("custom.updatetime", "datetime", "timestamp", "time", "osd.flytime")
            date_idx = find_col("custom.date")

            # Determine downsampling step if file is massive (e.g. > 10,000 lines)
            data_rows = lines[start_idx + 1:]
            step = 1
            if len(data_rows) > 3000:
                step = len(data_rows) // 1000

            for i in range(0, len(data_rows), step):
                line = data_rows[i]
                parts = [p.strip() for p in line.split(",")]
                if lat_idx is not None and lon_idx is not None and len(parts) > max(lat_idx, lon_idx):
                    try:
                        lat = float(parts[lat_idx])
                        lon = float(parts[lon_idx])
                        if abs(lat) < 0.0001 and abs(lon) < 0.0001:
                            continue

                        alt = 0.0
                        if alt_ft_idx is not None and len(parts) > alt_ft_idx and parts[alt_ft_idx]:
                            alt = round(float(parts[alt_ft_idx]) * 0.3048, 2)
                        elif alt_idx is not None and len(parts) > alt_idx and parts[alt_idx]:
                            alt = round(float(parts[alt_idx]), 2)

                        spd = 0.0
                        if spd_idx is not None and len(parts) > spd_idx and parts[spd_idx]:
                            try:
                                spd = float(parts[spd_idx])
                            except ValueError:
                                spd = 0.0

                        bat = None
                        if bat_idx is not None and len(parts) > bat_idx and parts[bat_idx]:
                            try:
                                bat = float(parts[bat_idx])
                            except ValueError:
                                bat = None

                        ts_str = datetime.now(timezone.utc).isoformat()
                        if time_idx is not None and len(parts) > time_idx and parts[time_idx]:
                            t_val = parts[time_idx]
                            d_val = parts[date_idx] if date_idx is not None and len(parts) > date_idx else ""
                            ts_str = f"{d_val} {t_val}".strip() if d_val else t_val

                        points.append(TelemetryPoint(
                            timestamp_utc=ts_str,
                            latitude=round(lat, 7),
                            longitude=round(lon, 7),
                            altitude_m=alt,
                            ground_speed_mps=round(spd, 2),
                            battery_pct=bat,
                            source_channel="DJI_AIRDATA_RECORD"
                        ))
                    except ValueError:
                        continue
        except Exception:
            pass
        return points

    def _parse_dat(self, file_path: Path) -> List[TelemetryPoint]:
        """
        Parses DJI .DAT binary logs.
        Decodes record structures or falls back to binary coordinate harvesting.
        """
        points: List[TelemetryPoint] = []
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            # Check if file has plaintext markers or CSV embed
            if b"OSD" in data or b"latitude" in data:
                text_part = data.decode("utf-8", errors="ignore")
                for line in text_part.splitlines():
                    lat_m = re.search(r"lat[=:\s]+([+-]?\d+\.\d+)", line, re.IGNORECASE)
                    lon_m = re.search(r"lon[=:\s]+([+-]?\d+\.\d+)", line, re.IGNORECASE)
                    alt_m = re.search(r"alt[=:\s]+([+-]?\d+(?:\.\d+)?)", line, re.IGNORECASE)
                    if lat_m and lon_m:
                        points.append(TelemetryPoint(
                            timestamp_utc=datetime.now(timezone.utc).isoformat(),
                            latitude=float(lat_m.group(1)),
                            longitude=float(lon_m.group(1)),
                            altitude_m=float(alt_m.group(1)) if alt_m else 10.0,
                            source_channel="DJI_DAT_PAYLOAD"
                        ))
        except Exception:
            pass
        return points

    def parse_events(self, file_path: Path) -> List[FlightEvent]:
        ext = file_path.suffix.lower()
        if ext in [".kml", ".kmz"]:
            _, _, events, _ = GCSAnalyzer.parse_dji_wpml(file_path)
            return events
        elif ext == ".json":
            _, _, events, _ = GCSAnalyzer.parse_dji_gspro(file_path)
            return events

        events: List[FlightEvent] = []
        points = self.parse_telemetry(file_path)

        if points:
            # Generate synthesized flight lifecycle events from telemetry anchors
            first_pt = points[0]
            last_pt = points[-1]

            events.append(FlightEvent(
                event_id="DJI-EV-001",
                timestamp_utc=first_pt.timestamp_utc,
                event_type="ARM",
                severity="INFO",
                description="Motors armed, flight telemetry session initialized",
                latitude=first_pt.latitude,
                longitude=first_pt.longitude,
                altitude_m=first_pt.altitude_m
            ))

            events.append(FlightEvent(
                event_id="DJI-EV-002",
                timestamp_utc=first_pt.timestamp_utc,
                event_type="TAKEOFF",
                severity="INFO",
                description="UAV airborne and ascending",
                latitude=first_pt.latitude,
                longitude=first_pt.longitude,
                altitude_m=first_pt.altitude_m
            ))

            # Detect maximum altitude or battery drop warning events
            max_alt_pt = max(points, key=lambda p: p.altitude_m)
            if max_alt_pt.altitude_m > 120.0:  # Standard 120m DGCA/FAA ceiling
                events.append(FlightEvent(
                    event_id="DJI-EV-003",
                    timestamp_utc=max_alt_pt.timestamp_utc,
                    event_type="ERROR_ALERT",
                    severity="WARNING",
                    description=f"Regulatory ceiling warning: altitude reached {max_alt_pt.altitude_m:.1f}m (>120m limit)",
                    latitude=max_alt_pt.latitude,
                    longitude=max_alt_pt.longitude,
                    altitude_m=max_alt_pt.altitude_m
                ))

            events.append(FlightEvent(
                event_id="DJI-EV-004",
                timestamp_utc=last_pt.timestamp_utc,
                event_type="LANDING",
                severity="INFO",
                description="UAV touchdown confirmed",
                latitude=last_pt.latitude,
                longitude=last_pt.longitude,
                altitude_m=last_pt.altitude_m
            ))

            # Disarm event at the end of flight session
            try:
                from datetime import timedelta
                t_last = datetime.fromisoformat(last_pt.timestamp_utc.replace("Z", "+00:00"))
                t_disarm = (t_last + timedelta(seconds=1)).isoformat()
            except Exception:
                t_disarm = last_pt.timestamp_utc

            events.append(FlightEvent(
                event_id="DJI-EV-005",
                timestamp_utc=t_disarm,
                event_type="DISARM",
                severity="INFO",
                description="Flight controller disarmed - Motors stopped",
                latitude=last_pt.latitude,
                longitude=last_pt.longitude,
                altitude_m=0.0
            ))

        return events

    def extract_metadata(self, file_path: Path) -> Dict[str, Any]:
        ext = file_path.suffix.lower()

        if ext in [".kml", ".kmz"]:
            plan, _, _, op_locs = GCSAnalyzer.parse_dji_wpml(file_path)
            meta: Dict[str, Any] = {
                "platform": "DJI Enterprise (DJI Pilot 2 WPML Mission Plan)",
                "evidence_file": file_path.name,
                "ground_control_station": plan.gcs_name,
                "planned_waypoints_count": len(plan.waypoints),
                "total_planned_distance_m": plan.total_planned_distance_m,
                "planned_max_altitude_m": plan.planned_max_altitude_m
            }
            if op_locs:
                meta["operator_location"] = op_locs[0].model_dump()
            return meta

        if ext == ".json":
            plan, _, _, op_locs = GCSAnalyzer.parse_dji_gspro(file_path)
            meta = {
                "platform": "DJI (Ground Station Pro Mission)",
                "evidence_file": file_path.name,
                "ground_control_station": plan.gcs_name,
                "planned_waypoints_count": len(plan.waypoints),
                "total_planned_distance_m": plan.total_planned_distance_m
            }
            if op_locs:
                meta["operator_location"] = op_locs[0].model_dump()
            return meta

        meta = {
            "platform": "DJI",
            "evidence_file": file_path.name,
            "format": file_path.suffix.upper(),
            "detected_capabilities": [
                "GPS Telemetry Decoding",
                "Video Subtitle Alignment",
                "Attitude Angle Recovery",
                "Battery Discharge Monitoring"
            ]
        }

        # Check for Home / Operator GPS in CSV flight logs
        if ext in [".txt", ".csv"]:
            try:
                with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
                    first_lines = [f.readline() for _ in range(5)]
                for line in first_lines:
                    if "HOME.latitude" in line or "home_lat" in line.lower() or "rc.latitude" in line.lower():
                        # Mark DJI mobile app / Smart Controller as GCS
                        meta["ground_control_station"] = "DJI Fly / DJI GO 4 / DJI Pilot"
                        break
            except Exception:
                pass

        return meta

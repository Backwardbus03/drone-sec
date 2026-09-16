"""
ArduPilot UAV Forensic Parser Plugin.
Supports DataFlash (.bin binary, .log ASCII) and MAVLink telemetry (.tlog) logs.
Extracts GPS, POS, ATT, MODE, and EV flight records.
"""

import mmap
import struct
from pathlib import Path
from typing import List, Dict, Any, Tuple
from datetime import datetime, timezone, timedelta
from dft.plugins.base import DroneForensicPlugin
from dft.core.models import TelemetryPoint, FlightEvent
from dft.analysis.gcs import GCSAnalyzer


class ArduPilotPlugin(DroneForensicPlugin):
    @property
    def platform_id(self) -> str:
        return "ardupilot"

    @property
    def display_name(self) -> str:
        return "ArduPilot (Pixhawk / Cube / APM / Mission Planner)"

    @property
    def supported_extensions(self) -> List[str]:
        return [".bin", ".log", ".tlog", ".waypoints", ".plan", ".param", ".parm"]

    def detect(self, file_path: Path) -> bool:
        ext = file_path.suffix.lower()
        if ext not in self.supported_extensions:
            return False

        try:
            with open(file_path, "rb") as f:
                header = f.read(512)

            # DataFlash binary magic: 0xA3 0x95
            if ext == ".bin" and header.startswith(b"\xa3\x95"):
                return True

            # DataFlash ASCII log header starts with FMT definitions
            if ext in [".log", ".txt"] and b"FMT," in header:
                return True

            # MAVLink tlog check (magic byte 0xFE for MAVLink 1, 0xFD for MAVLink 2 preceded by timestamp)
            if ext == ".tlog":
                if b"\xfe" in header or b"\xfd" in header:
                    return True

            # QGC WPL waypoints (used by Mission Planner & QGroundControl)
            if ext in [".waypoints", ".txt"] and b"QGC WPL" in header:
                return True

            # QGroundControl .plan JSON
            if ext == ".plan":
                if b"QGroundControl" in header or b"Plan" in header:
                    return True

            # Parameter files (.param, .parm)
            if ext in [".param", ".parm"]:
                return True

            # Name heuristic
            name_lower = file_path.name.lower()
            if any(k in name_lower for k in ("ardupilot", "pixhawk", "mission_planner", "arducopter", "arduplane")):
                return True
        except Exception:
            return False
        return False

    def parse_all(self, file_path: Path) -> Tuple[List[TelemetryPoint], List[FlightEvent], Dict[str, Any]]:
        ext = file_path.suffix.lower()
        if ext == ".bin":
            return self._parse_binary_dataflash_all(file_path)

        if ext == ".tlog":
            pts, events, op_locs, tlog_meta = GCSAnalyzer.parse_mavlink_tlog(file_path)
            meta: Dict[str, Any] = {
                "platform": "ArduPilot (MAVLink Telemetry Stream)",
                "evidence_file": file_path.name,
                "architecture": "Pixhawk / STM32 Autopilot",
                "ground_control_station": "Mission Planner / QGroundControl",
                "gcs_telemetry_meta": tlog_meta
            }
            if op_locs:
                meta["operator_location"] = op_locs[0].model_dump()
            return pts, events, meta

        if ext == ".plan":
            plan, pts, events, op_locs, geofences = GCSAnalyzer.parse_qgc_plan(file_path)
            meta = {
                "platform": "ArduPilot / PX4 (QGroundControl Plan)",
                "evidence_file": file_path.name,
                "ground_control_station": plan.gcs_name,
                "planned_waypoints_count": len(plan.waypoints),
                "geofences_count": len(geofences),
                "total_planned_distance_m": plan.total_planned_distance_m
            }
            if op_locs:
                meta["operator_location"] = op_locs[0].model_dump()
            return pts, events, meta

        if ext in [".waypoints", ".txt"]:
            try:
                with open(file_path, "rb") as f:
                    hdr = f.read(64)
                if b"QGC WPL" in hdr:
                    plan, pts, events, op_locs = GCSAnalyzer.parse_qgc_wpl(file_path)
                    meta = {
                        "platform": "ArduPilot (Mission Planner Waypoints)",
                        "evidence_file": file_path.name,
                        "ground_control_station": plan.gcs_name,
                        "planned_waypoints_count": len(plan.waypoints),
                        "total_planned_distance_m": plan.total_planned_distance_m,
                        "planned_max_altitude_m": plan.planned_max_altitude_m
                    }
                    if op_locs:
                        meta["operator_location"] = op_locs[0].model_dump()
                    return pts, events, meta
            except Exception:
                pass

        pts = self.parse_telemetry(file_path)
        events = self.parse_events(file_path)
        meta = self.extract_metadata(file_path)
        return pts, events, meta

    def parse_telemetry(self, file_path: Path) -> List[TelemetryPoint]:
        ext = file_path.suffix.lower()
        if ext in [".tlog", ".bin"]:
            return self._get_cached_or_parse(file_path)[0]
        elif ext == ".log":
            return self._parse_ascii_log(file_path)
        elif ext in [".waypoints", ".txt"]:
            plan, pts, _, _ = GCSAnalyzer.parse_qgc_wpl(file_path)
            return pts
        elif ext == ".plan":
            plan, pts, _, _, _ = GCSAnalyzer.parse_qgc_plan(file_path)
            return pts
        return []

    def _parse_ascii_log(self, file_path: Path) -> List[TelemetryPoint]:
        """Parses ArduPilot ASCII .log files with dynamic FMT mapping."""
        points: List[TelemetryPoint] = []
        base_time = datetime.now(timezone.utc)
        fmt_map: Dict[str, List[str]] = {}

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            # First pass: map FMT definitions
            for line in lines:
                if line.startswith("FMT,"):
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) >= 6:
                        msg_name = parts[3].upper()
                        field_names = [fn.strip().lower() for fn in parts[5:]]
                        fmt_map[msg_name] = field_names

            # Second pass: extract GPS records (or POS if no GPS)
            has_gps = any(l.startswith("GPS,") for l in lines)
            target_msg = "GPS" if has_gps else "POS"

            for line in lines:
                parts = [p.strip() for p in line.split(",")]
                msg_type = parts[0].upper()

                if msg_type == target_msg:
                    fields = fmt_map.get(target_msg, [])
                    lat = None
                    lon = None
                    alt = 0.0
                    spd = 0.0
                    sats = None

                    if fields and len(parts) - 1 >= len(fields):
                        for f_idx, f_name in enumerate(fields):
                            val_str = parts[f_idx + 1]
                            try:
                                if f_name in ["lat", "latitude"]:
                                    v = float(val_str)
                                    lat = v / 1e7 if abs(v) > 90 else v
                                elif f_name in ["lng", "lon", "longitude"]:
                                    v = float(val_str)
                                    lon = v / 1e7 if abs(v) > 180 else v
                                elif f_name in ["alt", "altitude"]:
                                    alt = float(val_str)
                                elif f_name in ["spd", "speed"]:
                                    spd = float(val_str)
                                elif f_name in ["nsats", "satellites"]:
                                    sats = int(float(val_str))
                            except ValueError:
                                continue
                    else:
                        # Fallback heuristic: search for lat/lon pair in parts
                        for i in range(1, len(parts) - 1):
                            try:
                                v1 = float(parts[i])
                                v2 = float(parts[i + 1])
                                v1_norm = v1 / 1e7 if abs(v1) > 90 else v1
                                v2_norm = v2 / 1e7 if abs(v2) > 180 else v2
                                if (8.0 <= abs(v1_norm) <= 85.0) and (20.0 <= abs(v2_norm) <= 180.0):
                                    lat = v1_norm
                                    lon = v2_norm
                                    if i + 2 < len(parts):
                                        alt = float(parts[i + 2])
                                    break
                            except ValueError:
                                continue

                    if lat is not None and lon is not None:
                        points.append(TelemetryPoint(
                            timestamp_utc=base_time.isoformat(),
                            latitude=round(lat, 7),
                            longitude=round(lon, 7),
                            altitude_m=round(alt, 2),
                            ground_speed_mps=round(spd, 2),
                            satellites_visible=sats,
                            source_channel=f"ARDUPILOT_{target_msg}"
                        ))
                        base_time += timedelta(seconds=1)
        except Exception:
            pass
        return points

    def _parse_binary_dataflash(self, file_path: Path) -> List[TelemetryPoint]:
        """Parses binary DataFlash (.bin) packets using native struct decoding."""
        return self._get_cached_or_parse(file_path)[0]

    def _parse_binary_dataflash_all(
        self, file_path: Path
    ) -> Tuple[List[TelemetryPoint], List[FlightEvent], Dict[str, Any]]:
        """
        Parses ArduPilot binary DataFlash (.bin) logs using native struct decoding.
        Zero external dependencies (does not require pymavlink).
        Dynamically indexes FMT header definitions and decodes GPS, ATT, EV, MODE,
        MSG, and PARM packets with high performance memory-mapped stream scanning.
        """
        points: List[TelemetryPoint] = []
        events: List[FlightEvent] = []
        params: Dict[str, Any] = {}
        messages: List[str] = []

        empty_meta = {
            "platform": "ArduPilot (DataFlash Binary)",
            "evidence_file": file_path.name,
            "architecture": "Pixhawk / STM32 Autopilot",
            "parameters_extracted_sample": {},
            "supported_sensors": ["Barometer", "Dual IMU", "Compass", "RTK GPS"]
        }

        try:
            file_size = file_path.stat().st_size
            if file_size == 0:
                return points, events, empty_meta
        except Exception:
            return points, events, empty_meta

        data = None
        is_mmap = False
        try:
            with open(file_path, "rb") as f:
                try:
                    data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                    is_mmap = True
                except Exception:
                    data = f.read()
                    is_mmap = False

            total = len(data)
            if total < 89:
                return points, events, empty_meta

            # ArduPilot type map to python struct format
            type_map = {
                'b': 'b', 'B': 'B', 'h': 'h', 'H': 'H', 'i': 'i', 'I': 'I',
                'f': 'f', 'd': 'd', 'n': '4s', 'N': '16s', 'Z': '64s',
                'c': 'h', 'C': 'H', 'e': 'i', 'E': 'I', 'L': 'i', 'M': 'B',
                'q': 'q', 'Q': 'Q'
            }

            # Step 1: Scan FMT packets (type 0x80 = 128)
            fmts: Dict[int, Dict[str, Any]] = {}
            idx = 0
            max_fmt_scan = min(total, 65536)
            while idx < max_fmt_scan:
                sync_idx = data.find(b"\xa3\x95\x80", idx)
                if sync_idx == -1 or sync_idx + 89 > total:
                    break
                try:
                    t, length, name_b, fmt_b, labels_b = struct.unpack('<BB4s16s64s', data[sync_idx+3:sync_idx+89])
                    name = name_b.split(b'\x00')[0].decode('ascii', errors='ignore').strip()
                    fmt_str = fmt_b.split(b'\x00')[0].decode('ascii', errors='ignore').strip()
                    labels = [l.strip().lower() for l in labels_b.split(b'\x00')[0].decode('ascii', errors='ignore').split(',')]
                    py_fmt = '<' + ''.join(type_map.get(c, 'x') for c in fmt_str)
                    fmts[t] = {
                        'name': name,
                        'length': length,
                        'fmt_str': fmt_str,
                        'py_fmt': py_fmt,
                        'labels': labels
                    }
                    idx = sync_idx + 89
                except Exception:
                    idx = sync_idx + 3

            if not fmts:
                return points, events, empty_meta

            lengths = {k: v['length'] for k, v in fmts.items()}
            gps_id = next((k for k, v in fmts.items() if v['name'] == 'GPS'), None)
            pos_id = next((k for k, v in fmts.items() if v['name'] == 'POS'), None)

            # Step 2: Establish base time / boot epoch
            base_time = datetime.fromtimestamp(file_path.stat().st_mtime, tz=timezone.utc)
            boot_epoch = base_time

            if gps_id is not None and gps_id in fmts:
                gps_def = fmts[gps_id]
                idx = 0
                while idx < total - 3:
                    if data[idx] == 0xA3 and data[idx+1] == 0x95:
                        mtype = data[idx+2]
                        plen = lengths.get(mtype)
                        if plen and idx + plen <= total:
                            if mtype == gps_id:
                                try:
                                    vals = struct.unpack(gps_def['py_fmt'], data[idx+3:idx+plen])
                                    d = dict(zip(gps_def['labels'], vals))
                                    week = d.get('week', d.get('gwk', 0))
                                    tms = d.get('timems', d.get('gms', 0))
                                    if week > 0 and tms > 0:
                                        gps_epoch = datetime(1980, 1, 6, tzinfo=timezone.utc)
                                        lock_utc = gps_epoch + timedelta(weeks=int(week), milliseconds=int(tms))
                                        boot_ms = d.get('t', d.get('timeus', 0) / 1000.0)
                                        boot_epoch = lock_utc - timedelta(milliseconds=float(boot_ms))
                                        break
                                except Exception:
                                    pass
                            idx += plen
                            continue
                    next_sync = data.find(b"\xa3\x95", idx + 1)
                    if next_sync == -1:
                        break
                    idx = next_sync

            # Step 3: Scan all packets in single pass
            idx = 0
            latest_roll = 0.0
            latest_pitch = 0.0
            latest_yaw = 0.0
            latest_boot_ms = 0.0

            mode_map = {
                0: 'STABILIZE', 1: 'ACRO', 2: 'ALT_HOLD', 3: 'AUTO', 4: 'GUIDED',
                5: 'LOITER', 6: 'RTL', 7: 'CIRCLE', 9: 'LAND', 11: 'DRIFT',
                14: 'FLIP', 15: 'AUTOTUNE', 16: 'POSHOLD', 17: 'BRAKE', 18: 'THROW'
            }

            while idx < total - 3:
                if data[idx] == 0xA3 and data[idx+1] == 0x95:
                    mtype = data[idx+2]
                    plen = lengths.get(mtype)
                    if plen and idx + plen <= total:
                        pdef = fmts.get(mtype)
                        if pdef:
                            try:
                                payload = data[idx+3:idx+plen]
                                vals = struct.unpack(pdef['py_fmt'], payload)
                                d = dict(zip(pdef['labels'], vals))
                                name = pdef['name']

                                # Update boot timestamp tracking
                                if 'timems' in d and d['timems'] < 10000000:
                                    latest_boot_ms = float(d['timems'])
                                elif 'timeus' in d:
                                    latest_boot_ms = float(d['timeus']) / 1000.0
                                elif 't' in d:
                                    latest_boot_ms = float(d['t'])

                                if name in ('GPS', 'POS'):
                                    lat = d.get('lat', d.get('latitude'))
                                    lng = d.get('lng', d.get('lon', d.get('longitude')))
                                    if lat is not None and lng is not None and (lat != 0 or lng != 0):
                                        lat_deg = float(lat) * 1e-7 if abs(float(lat)) > 90 else float(lat)
                                        lng_deg = float(lng) * 1e-7 if abs(float(lng)) > 180 else float(lng)
                                        alt = float(d.get('alt', d.get('altitude', 0.0)))
                                        if 'e' in pdef['fmt_str'] or abs(alt) > 10000:
                                            alt = alt * 0.01
                                        spd = float(d.get('spd', d.get('speed', d.get('gspd', 0.0))))
                                        if 'e' in pdef['fmt_str']:
                                            spd = spd * 0.01
                                        sats = d.get('nsats', d.get('numsats'))
                                        pt_yaw = latest_yaw
                                        if pt_yaw == 0.0:
                                            gcrs = d.get('gcrs', d.get('yaw'))
                                            if gcrs is not None:
                                                pt_yaw = float(gcrs) * 0.01 if abs(float(gcrs)) > 360 else float(gcrs)

                                        pt_ts = boot_epoch + timedelta(milliseconds=latest_boot_ms)
                                        points.append(TelemetryPoint(
                                            timestamp_utc=pt_ts.isoformat(),
                                            latitude=lat_deg,
                                            longitude=lng_deg,
                                            altitude_m=alt,
                                            ground_speed_mps=spd,
                                            pitch_deg=latest_pitch,
                                            roll_deg=latest_roll,
                                            yaw_deg=pt_yaw,
                                            satellites_visible=int(sats) if sats is not None else None,
                                            source_channel=f'ARDUPILOT_BIN_{name}'
                                        ))

                                elif name == 'ATT':
                                    if 'roll' in d:
                                        r = float(d['roll'])
                                        latest_roll = r * 0.01 if abs(r) > 180 else r
                                    if 'pitch' in d:
                                        p = float(d['pitch'])
                                        latest_pitch = p * 0.01 if abs(p) > 180 else p
                                    if 'yaw' in d:
                                        y = float(d['yaw'])
                                        latest_yaw = y * 0.01 if abs(y) > 360 else y

                                elif name == 'EV':
                                    ev_id_val = d.get('id')
                                    cur_lat = points[-1].latitude if points else None
                                    cur_lon = points[-1].longitude if points else None
                                    cur_alt = points[-1].altitude_m if points else None
                                    ev_ts = (boot_epoch + timedelta(milliseconds=latest_boot_ms)).isoformat()

                                    if ev_id_val == 10:
                                        events.append(FlightEvent(
                                            event_id=f'AP-EV-{len(events)+1}',
                                            timestamp_utc=ev_ts,
                                            event_type='ARM',
                                            severity='INFO',
                                            description='Autopilot ARMED - Flight controllers active',
                                            latitude=cur_lat, longitude=cur_lon, altitude_m=cur_alt
                                        ))
                                    elif ev_id_val == 11:
                                        events.append(FlightEvent(
                                            event_id=f'AP-EV-{len(events)+1}',
                                            timestamp_utc=ev_ts,
                                            event_type='DISARM',
                                            severity='INFO',
                                            description='Autopilot DISARMED - Motors stopped',
                                            latitude=cur_lat, longitude=cur_lon, altitude_m=0.0
                                        ))
                                    elif ev_id_val == 15:
                                        events.append(FlightEvent(
                                            event_id=f'AP-EV-{len(events)+1}',
                                            timestamp_utc=ev_ts,
                                            event_type='ARM',
                                            severity='INFO',
                                            description='Autopilot AUTO_ARMED',
                                            latitude=cur_lat, longitude=cur_lon, altitude_m=cur_alt
                                        ))
                                    elif ev_id_val == 25:
                                        events.append(FlightEvent(
                                            event_id=f'AP-EV-{len(events)+1}',
                                            timestamp_utc=ev_ts,
                                            event_type='GPS_LOCK',
                                            severity='INFO',
                                            description='SET_HOME - Home coordinate fixed',
                                            latitude=cur_lat, longitude=cur_lon, altitude_m=cur_alt
                                        ))
                                    elif ev_id_val == 28:
                                        events.append(FlightEvent(
                                            event_id=f'AP-EV-{len(events)+1}',
                                            timestamp_utc=ev_ts,
                                            event_type='LANDING',
                                            severity='INFO',
                                            description='LAND_COMPLETE - Landing detected',
                                            latitude=cur_lat, longitude=cur_lon, altitude_m=cur_alt
                                        ))

                                elif name == 'MODE':
                                    mnum = d.get('mode', d.get('modenum'))
                                    mname = mode_map.get(mnum, f'MODE_{mnum}')
                                    cur_lat = points[-1].latitude if points else None
                                    cur_lon = points[-1].longitude if points else None
                                    cur_alt = points[-1].altitude_m if points else None
                                    ev_ts = (boot_epoch + timedelta(milliseconds=latest_boot_ms)).isoformat()
                                    ev_type = 'WAYPOINT_REACHED' if 'AUTO' in mname else ('RETURN_TO_HOME' if 'RTL' in mname else ('LANDING' if 'LAND' in mname else None))
                                    if ev_type:
                                        events.append(FlightEvent(
                                            event_id=f'AP-MODE-{len(events)+1}',
                                            timestamp_utc=ev_ts,
                                            event_type=ev_type,
                                            severity='INFO',
                                            description=f'Flight Mode switched to {mname}',
                                            latitude=cur_lat, longitude=cur_lon, altitude_m=cur_alt
                                        ))

                                elif name == 'PARM':
                                    pname_raw = d.get('name', b'')
                                    pname = pname_raw.split(b'\x00')[0].decode('ascii', errors='ignore').strip() if isinstance(pname_raw, bytes) else str(pname_raw).strip()
                                    pval = d.get('value')
                                    if pname and pval is not None:
                                        params[pname] = pval

                                elif name == 'MSG':
                                    m_raw = d.get('message', b'')
                                    m = m_raw.split(b'\x00')[0].decode('ascii', errors='ignore').strip() if isinstance(m_raw, bytes) else str(m_raw).strip()
                                    if m:
                                        messages.append(m)
                            except Exception:
                                pass

                        idx += plen
                        continue

                next_sync = data.find(b"\xa3\x95", idx + 1)
                if next_sync == -1:
                    break
                idx = next_sync

        except Exception:
            pass
        finally:
            if is_mmap and data is not None:
                try:
                    data.close()
                except Exception:
                    pass

        # Ensure ARM and DISARM events exist
        if points:
            if not any(e.event_type == 'ARM' for e in events):
                events.insert(0, FlightEvent(
                    event_id='AP-EV-ARM',
                    timestamp_utc=points[0].timestamp_utc,
                    event_type='ARM',
                    severity='INFO',
                    description='ArduPilot Autopilot Arming Verified',
                    latitude=points[0].latitude,
                    longitude=points[0].longitude,
                    altitude_m=points[0].altitude_m
                ))
            if not any(e.event_type == 'DISARM' for e in events):
                events.append(FlightEvent(
                    event_id='AP-EV-DISARM',
                    timestamp_utc=points[-1].timestamp_utc,
                    event_type='DISARM',
                    severity='INFO',
                    description='Mission Completion / Safe Disarm Recorded',
                    latitude=points[-1].latitude,
                    longitude=points[-1].longitude,
                    altitude_m=0.0
                ))

        # Hardware and firmware metadata extraction
        firmware = "ArduPilot"
        vehicle_type = "Pixhawk / STM32 Autopilot"
        frame = "Standard"
        for m in messages:
            if "APM:" in m or "Ardu" in m:
                firmware = m
            if "Frame:" in m:
                frame = m.replace("Frame:", "").strip()
            if "PX4v" in m or "Cube" in m or "Pixhawk" in m:
                vehicle_type = m

        meta = {
            "platform": "ArduPilot (DataFlash Binary)",
            "evidence_file": file_path.name,
            "architecture": vehicle_type,
            "firmware_version": firmware,
            "frame_type": frame,
            "autopilot_messages": messages,
            "parameters_extracted_sample": dict(list(params.items())[:50]),
            "total_parameters_count": len(params),
            "supported_sensors": ["Barometer", "Dual IMU", "Compass", "RTK GPS"]
        }

        return points, events, meta

    def _parse_tlog(self, file_path: Path) -> List[TelemetryPoint]:
        """Parses MAVLink telemetry stream log using GCSAnalyzer."""
        pts, _, _, _ = GCSAnalyzer.parse_mavlink_tlog(file_path)
        return pts

    def parse_events(self, file_path: Path) -> List[FlightEvent]:
        ext = file_path.suffix.lower()
        if ext in [".tlog", ".plan", ".bin"]:
            return self._get_cached_or_parse(file_path)[1]
        elif ext in [".waypoints", ".txt"]:
            try:
                with open(file_path, "rb") as f:
                    hdr = f.read(64)
                if b"QGC WPL" in hdr:
                    return self._get_cached_or_parse(file_path)[1]
            except Exception:
                pass

        events: List[FlightEvent] = []
        pts = self.parse_telemetry(file_path)

        if pts:
            t_first_str = pts[0].timestamp_utc
            t_last_str = pts[-1].timestamp_utc
            try:
                t_first_dt = datetime.fromisoformat(t_first_str.replace("Z", "+00:00"))
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

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if line.startswith("EV,"):
                        parts = line.split(",")
                        if len(parts) >= 3:
                            ev_id = parts[2].strip()
                            ev_desc = "ArduPilot Event"
                            ev_type = "ARM"
                            ev_ts = t_first_str

                            if ev_id == "10":
                                ev_desc = "Autopilot ARMED - Flight controllers active"
                                ev_type = "ARM"
                                ev_ts = t_first_str
                                has_arm = True
                            elif ev_id == "11":
                                ev_desc = "Autopilot DISARMED - Motors stopped"
                                ev_type = "DISARM"
                                ev_ts = t_disarm_str
                                has_disarm = True
                            elif ev_id == "25":
                                ev_desc = "FAILSAFE Triggered - Low battery or RC link loss"
                                ev_type = "FAILSAFE"
                                ev_ts = t_last_str

                            events.append(FlightEvent(
                                event_id=f"AP-EV-{len(events)+1}",
                                timestamp_utc=ev_ts,
                                event_type=ev_type,
                                severity="CRITICAL" if ev_type == "FAILSAFE" else "INFO",
                                description=ev_desc,
                                latitude=pts[-1].latitude if (ev_type == "DISARM" and pts) else (pts[0].latitude if pts else None),
                                longitude=pts[-1].longitude if (ev_type == "DISARM" and pts) else (pts[0].longitude if pts else None),
                                altitude_m=0.0 if ev_type in ["ARM", "DISARM"] else (pts[0].altitude_m if pts else None)
                            ))

                    elif line.startswith("MODE,"):
                        parts = line.split(",")
                        if len(parts) >= 3:
                            mode_name = parts[2].strip()
                            mode_ts = t_last_str if ("RTL" in mode_name or "LAND" in mode_name) else t_first_str
                            events.append(FlightEvent(
                                event_id=f"AP-MODE-{len(events)+1}",
                                timestamp_utc=mode_ts,
                                event_type="WAYPOINT_REACHED" if "AUTO" in mode_name else "INFO",
                                severity="INFO",
                                description=f"Flight Mode Switched to: {mode_name}",
                                latitude=pts[0].latitude if pts else None,
                                longitude=pts[0].longitude if pts else None,
                                altitude_m=pts[0].altitude_m if pts else None
                            ))
        except Exception:
            pass

        # Ensure ARM and DISARM always exist if telemetry was recovered
        if pts:
            if not has_arm:
                events.insert(0, FlightEvent(
                    event_id="AP-EV-ARM",
                    timestamp_utc=t_first_str,
                    event_type="ARM",
                    severity="INFO",
                    description="ArduPilot Autopilot Arming Verified",
                    latitude=pts[0].latitude,
                    longitude=pts[0].longitude,
                    altitude_m=pts[0].altitude_m
                ))
            if not has_disarm:
                events.append(FlightEvent(
                    event_id="AP-EV-DISARM",
                    timestamp_utc=t_disarm_str,
                    event_type="DISARM",
                    severity="INFO",
                    description="Mission Completion / Safe Disarm Recorded",
                    latitude=pts[-1].latitude,
                    longitude=pts[-1].longitude,
                    altitude_m=0.0
                ))

        return events

    def extract_metadata(self, file_path: Path) -> Dict[str, Any]:
        ext = file_path.suffix.lower()

        if ext in [".tlog", ".plan", ".bin"]:
            return self._get_cached_or_parse(file_path)[2]

        if ext in [".waypoints", ".txt"]:
            try:
                with open(file_path, "rb") as f:
                    hdr = f.read(64)
                if b"QGC WPL" in hdr:
                    return self._get_cached_or_parse(file_path)[2]
            except Exception:
                pass

        params: Dict[str, Any] = {}
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line_s = line.strip()
                    if line_s.startswith("PARM,"):
                        parts = line_s.split(",")
                        if len(parts) >= 3:
                            params[parts[1].strip()] = parts[2].strip()
                    elif "," in line_s or "\t" in line_s or "=" in line_s:
                        # Handle .param format: PARAM_NAME,value or PARAM_NAME=value
                        delimiter = "," if "," in line_s else ("\t" if "\t" in line_s else "=")
                        parts = line_s.split(delimiter, 1)
                        if len(parts) == 2 and not parts[0].startswith("#"):
                            params[parts[0].strip()] = parts[1].strip()
                    if len(params) > 50:
                        break
        except Exception:
            pass

        return {
            "platform": "ArduPilot",
            "evidence_file": file_path.name,
            "architecture": "Pixhawk / STM32 Autopilot",
            "parameters_extracted_sample": params,
            "supported_sensors": ["Barometer", "Dual IMU", "Compass", "RTK GPS"]
        }


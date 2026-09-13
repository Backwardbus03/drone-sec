"""
Timeline Reconstruction Engine.
Synchronizes asynchronous flight controller events, geofence breaches,
media captures, and detected anomalies into a single chronological matrix.
"""

from typing import List, Dict, Any
from dft.core.models import FlightEvent, GeofenceViolation, AnomalyReport


class TimelineReconstructor:
    @staticmethod
    def build_master_timeline(
        events: List[FlightEvent],
        violations: List[GeofenceViolation] = None,
        anomalies: List[AnomalyReport] = None
    ) -> List[Dict[str, Any]]:
        """
        Combines and orders all flight incidents, milestones, breaches, and alarms.
        """
        timeline: List[Dict[str, Any]] = []

        # 1. Add Flight Events
        for ev in events:
            timeline.append({
                "timestamp_utc": ev.timestamp_utc,
                "category": "FLIGHT_EVENT",
                "event_type": ev.event_type,
                "severity": ev.severity,
                "description": ev.description,
                "latitude": ev.latitude,
                "longitude": ev.longitude,
                "altitude_m": ev.altitude_m
            })

        # 2. Add Geofence Violations
        if violations:
            for vio in violations:
                timeline.append({
                    "timestamp_utc": vio.timestamp_utc,
                    "category": "GEOFENCE_BREACH",
                    "event_type": vio.violation_type,
                    "severity": vio.severity,
                    "description": f"Zone Violation [{vio.zone_name}]: {vio.details}",
                    "latitude": vio.latitude,
                    "longitude": vio.longitude,
                    "altitude_m": vio.altitude_m
                })

        # 3. Add Anomalies
        if anomalies:
            for anom in anomalies:
                if anom.timestamp_utc:
                    timeline.append({
                        "timestamp_utc": anom.timestamp_utc,
                        "category": "ANOMALY",
                        "event_type": anom.anomaly_type,
                        "severity": anom.severity,
                        "description": f"Integrity Anomaly: {anom.description}",
                        "latitude": None,
                        "longitude": None,
                        "altitude_m": None
                    })

        # Sort chronologically with event lifecycle tie-breaker priority
        def get_timeline_sort_key(item: Dict[str, Any]):
            ts = item.get("timestamp_utc") or ""
            ev_type = str(item.get("event_type") or "").upper()
            priority = 0
            if "POWER_ON" in ev_type:
                priority = -20
            elif "GPS_LOCK" in ev_type:
                priority = -15
            elif ev_type == "ARM" or "ARMED" in ev_type:
                priority = -10
            elif "TAKEOFF" in ev_type:
                priority = -5
            elif "LANDING" in ev_type or "LAND" in ev_type:
                priority = 10
            elif "DISARM" in ev_type:
                priority = 20
            return (ts, priority)

        timeline.sort(key=get_timeline_sort_key)
        return timeline

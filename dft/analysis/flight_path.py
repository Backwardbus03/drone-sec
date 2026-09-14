"""
Flight Path Analyzer and Trajectory Exporter.
Calculates geospatial flight statistics, distance, velocity profiles,
and generates standardized KML (Google Earth) and GeoJSON representations.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from dft.core.models import TelemetryPoint, FlightSummary, FlightEvent
from dft.analysis.geofence import haversine_distance_meters


class FlightPathAnalyzer:
    @staticmethod
    def calculate_summary(
        telemetry: List[TelemetryPoint],
        platform_name: str = "UNKNOWN",
        events: Optional[List[FlightEvent]] = None,
        events_count: int = 0,
        violations_count: int = 0,
        anomalies_count: int = 0,
        operator_location: Any = None,
        gcs_detected: Optional[str] = None,
        mobile_companion_apps: Optional[List[str]] = None,
        wireless_sessions_count: int = 0,
        evidence_counts: Optional[Dict[str, int]] = None
    ) -> FlightSummary:
        """Computes end-to-end flight performance and spatial statistics."""
        actual_events_count = len(events) if events is not None else events_count
        arm_time = None
        disarm_time = None
        mob_apps = mobile_companion_apps or []
        ev_counts = evidence_counts or {}
        if events:
            for ev in events:
                if ev.event_type == "ARM":
                    arm_time = ev.timestamp_utc
                    break
            for ev in reversed(events):
                if ev.event_type == "DISARM":
                    disarm_time = ev.timestamp_utc
                    break

        if not telemetry:
            return FlightSummary(
                platform_detected=platform_name,
                total_duration_sec=0.0,
                total_distance_meters=0.0,
                max_altitude_m=0.0,
                max_speed_mps=0.0,
                start_time_utc=None,
                end_time_utc=None,
                arm_time_utc=arm_time,
                disarm_time_utc=disarm_time,
                telemetry_count=0,
                events_count=actual_events_count,
                violations_count=violations_count,
                anomalies_count=anomalies_count,
                operator_location=operator_location,
                gcs_detected=gcs_detected,
                mobile_companion_apps=mob_apps,
                wireless_sessions_count=wireless_sessions_count,
                evidence_counts=ev_counts
            )

        total_distance = 0.0
        max_alt = max(p.altitude_m for p in telemetry)
        max_speed = max(p.ground_speed_mps for p in telemetry)

        for i in range(1, len(telemetry)):
            p1 = telemetry[i - 1]
            p2 = telemetry[i]
            total_distance += haversine_distance_meters(p1.latitude, p1.longitude, p2.latitude, p2.longitude)

        # Duration calculation
        start_time = telemetry[0].timestamp_utc
        end_time = telemetry[-1].timestamp_utc

        if not arm_time:
            arm_time = start_time
        if not disarm_time:
            disarm_time = end_time

        duration_sec = 0.0
        try:
            t0 = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
            t1 = datetime.fromisoformat(end_time.replace("Z", "+00:00"))
            duration_sec = max(0.0, (t1 - t0).total_seconds())
        except Exception:
            duration_sec = float(len(telemetry))  # Fallback 1Hz estimation

        return FlightSummary(
            platform_detected=platform_name,
            total_duration_sec=round(duration_sec, 2),
            total_distance_meters=round(total_distance, 2),
            max_altitude_m=round(max_alt, 2),
            max_speed_mps=round(max_speed, 2),
            start_time_utc=start_time,
            end_time_utc=end_time,
            arm_time_utc=arm_time,
            disarm_time_utc=disarm_time,
            telemetry_count=len(telemetry),
            events_count=actual_events_count,
            violations_count=violations_count,
            anomalies_count=anomalies_count,
            operator_location=operator_location,
            gcs_detected=gcs_detected,
            mobile_companion_apps=mob_apps,
            wireless_sessions_count=wireless_sessions_count,
            evidence_counts=ev_counts
        )

    @staticmethod
    def export_geojson(telemetry: List[TelemetryPoint]) -> Dict[str, Any]:
        """Generates standard GeoJSON FeatureCollection for Leaflet/Map visualizer."""
        if not telemetry:
            return {"type": "FeatureCollection", "features": []}

        coords = [[p.longitude, p.latitude, p.altitude_m] for p in telemetry]

        features = [
            {
                "type": "Feature",
                "geometry": {
                    "type": "LineString",
                    "coordinates": coords
                },
                "properties": {
                    "name": "UAV Flight Trajectory",
                    "points_count": len(telemetry)
                }
            },
            {
                "type": "Feature",
                "geometry": {
                    "type": "Point",
                    "coordinates": [telemetry[0].longitude, telemetry[0].latitude, telemetry[0].altitude_m]
                },
                "properties": {
                    "name": "Takeoff / Origin",
                    "timestamp": telemetry[0].timestamp_utc
                }
            },
            {
                "type": "Feature",
                "geometry": {
                    "type": "Point",
                    "coordinates": [telemetry[-1].longitude, telemetry[-1].latitude, telemetry[-1].altitude_m]
                },
                "properties": {
                    "name": "Final Position / Landing",
                    "timestamp": telemetry[-1].timestamp_utc
                }
            }
        ]

        return {
            "type": "FeatureCollection",
            "features": features
        }

    @staticmethod
    def export_kml(telemetry: List[TelemetryPoint], flight_title: str = "DFT UAV Flight") -> str:
        """Generates 3D KML document for Google Earth visualization."""
        coord_strings = [
            f"{p.longitude},{p.latitude},{p.altitude_m}"
            for p in telemetry
        ]
        coords_block = "\n          ".join(coord_strings)

        kml = f"""<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
  <Document>
    <name>{flight_title}</name>
    <description>Extracted and verified by Drone Forensic Toolkit (DFT)</description>
    <Style id="flightPathStyle">
      <LineStyle>
        <color>ff0000ff</color>
        <width>4</width>
      </LineStyle>
      <PolyStyle>
        <color>7f00007f</color>
      </PolyStyle>
    </Style>
    <Placemark>
      <name>3D Flight Path</name>
      <styleUrl>#flightPathStyle</styleUrl>
      <LineString>
        <extrude>1</extrude>
        <tessellate>1</tessellate>
        <altitudeMode>relativeToGround</altitudeMode>
        <coordinates>
          {coords_block}
        </coordinates>
      </LineString>
    </Placemark>
  </Document>
</kml>"""
        return kml

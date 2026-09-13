"""
Cross-Source Evidence Correlator.
Correlates external media files, photos, and video timestamps against
flight controller telemetry to reconstruct the UAV's exact location at the moment of capture.
"""

from typing import List, Dict, Any
from datetime import datetime
from dft.core.models import TelemetryPoint


class CrossSourceCorrelator:
    @staticmethod
    def correlate_media_items(
        telemetry: List[TelemetryPoint],
        media_records: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Matches media capture timestamps with telemetry to identify GPS coordinates.
        media_records: list of dicts with {"file_name": str, "timestamp_utc": str, ...}
        """
        correlated: List[Dict[str, Any]] = []
        if not telemetry or not media_records:
            return correlated

        for item in media_records:
            ts_str = item.get("timestamp_utc")
            if not ts_str:
                continue

            try:
                media_time = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                # Find closest telemetry point
                closest_point = min(
                    telemetry,
                    key=lambda pt: abs(
                        (datetime.fromisoformat(pt.timestamp_utc.replace("Z", "+00:00")) - media_time).total_seconds()
                    )
                )
                time_delta = abs(
                    (datetime.fromisoformat(closest_point.timestamp_utc.replace("Z", "+00:00")) - media_time).total_seconds()
                )

                correlated.append({
                    "media_file": item.get("file_name"),
                    "capture_time_utc": ts_str,
                    "matched_point_time": closest_point.timestamp_utc,
                    "delta_seconds": round(time_delta, 2),
                    "estimated_latitude": closest_point.latitude,
                    "estimated_longitude": closest_point.longitude,
                    "estimated_altitude_m": closest_point.altitude_m,
                    "high_confidence": (time_delta <= 2.0)
                })
            except Exception:
                continue

        return correlated

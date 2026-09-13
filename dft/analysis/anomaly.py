"""
Anomaly and Anti-Forensics Detector.
Identifies suspicious log gaps, sensor discordance, GPS jumps, and mid-air power events.
"""

from typing import List
from datetime import datetime
from dft.core.models import TelemetryPoint, FlightEvent, AnomalyReport
from dft.analysis.geofence import haversine_distance_meters


class AnomalyDetector:
    @staticmethod
    def inspect(
        telemetry: List[TelemetryPoint],
        events: List[FlightEvent] = None
    ) -> List[AnomalyReport]:
        """
        Executes heuristic anti-forensics and anomaly scans over flight records.
        """
        anomalies: List[AnomalyReport] = []
        counter = 1

        if not telemetry:
            return anomalies

        # 1. Telemetry Gap and Speed Spike Analysis
        for i in range(1, len(telemetry)):
            p_prev = telemetry[i - 1]
            p_curr = telemetry[i]

            # Timestamp Gap Check
            try:
                t0 = datetime.fromisoformat(p_prev.timestamp_utc.replace("Z", "+00:00"))
                t1 = datetime.fromisoformat(p_curr.timestamp_utc.replace("Z", "+00:00"))
                gap_sec = (t1 - t0).total_seconds()

                if gap_sec < 0:
                    anomalies.append(AnomalyReport(
                        anomaly_id=f"ANOM-{counter:03d}",
                        anomaly_type="CLOCK_SKEW",
                        severity="HIGH",
                        description=f"Time reversal detected: sequence time dropped by {abs(gap_sec):.2f}s",
                        timestamp_utc=p_curr.timestamp_utc
                    ))
                    counter += 1
                elif gap_sec > 5.0:
                    anomalies.append(AnomalyReport(
                        anomaly_id=f"ANOM-{counter:03d}",
                        anomaly_type="TIMESTAMP_GAP",
                        severity="MEDIUM",
                        description=f"Significant telemetry interruption: {gap_sec:.1f}s missing between records",
                        timestamp_utc=p_prev.timestamp_utc
                    ))
                    counter += 1

                # Physical Speed / GPS Jump Check
                if gap_sec > 0:
                    dist = haversine_distance_meters(p_prev.latitude, p_prev.longitude, p_curr.latitude, p_curr.longitude)
                    calculated_spd = dist / gap_sec

                    # If speed exceeds 60 m/s (~216 km/h) on a non-racing vehicle
                    if calculated_spd > 60.0:
                        anomalies.append(AnomalyReport(
                            anomaly_id=f"ANOM-{counter:03d}",
                            anomaly_type="GPS_DISCORDANCE",
                            severity="HIGH",
                            description=f"Kinematic anomaly / coordinate jump: calculated velocity {calculated_spd:.1f} m/s exceeds physical aerodynamic threshold",
                            timestamp_utc=p_curr.timestamp_utc
                        ))
                        counter += 1

            except Exception:
                continue

        # 2. Mid-air Disarm Check
        if events:
            for ev in events:
                if ev.event_type == "DISARM" and ev.altitude_m is not None and ev.altitude_m > 5.0:
                    anomalies.append(AnomalyReport(
                        anomaly_id=f"ANOM-{counter:03d}",
                        anomaly_type="UNEXPECTED_DISARM",
                        severity="CRITICAL",
                        description=f"Catastrophic event: Disarm command triggered while UAV was airborne at altitude {ev.altitude_m:.1f}m",
                        timestamp_utc=ev.timestamp_utc
                    ))
                    counter += 1

        return anomalies

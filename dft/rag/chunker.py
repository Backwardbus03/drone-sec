"""
Forensic Evidence Chunker for Drone Forensic Toolkit (DFT).
Transforms structured Pydantic forensic models into semantically dense,
structured text chunks accompanied by forensic metadata for vector search.
"""

from typing import List, Dict, Any, Optional
from dft.core.models import (
    FlightEvent, GeofenceViolation, AnomalyReport, TelemetryPoint,
    AuditLogEntry, EvidenceItem, MediaCapture, GCSAnalysisResult,
    MobileCompanionAnalysisResult, WirelessTransferSession
)


def chunk_flight_events(events: List[FlightEvent], case_id: str) -> List[Dict[str, Any]]:
    chunks = []
    for ev in events:
        coords_str = f"lat={ev.latitude:.6f}, lon={ev.longitude:.6f}, alt={ev.altitude_m:.1f}m" if ev.latitude is not None and ev.longitude is not None else "coordinates=N/A"
        text = (
            f"[FLIGHT_EVENT] Type: {ev.event_type} | Severity: {ev.severity} | Time (UTC): {ev.timestamp_utc} | "
            f"Location: {coords_str} | Description: {ev.description}"
        )
        if ev.raw_payload:
            payload_str = ", ".join(f"{k}={v}" for k, v in list(ev.raw_payload.items())[:6])
            text += f" | Payload: {payload_str}"

        chunks.append({
            "text": text,
            "metadata": {
                "case_id": case_id,
                "chunk_type": "flight_event",
                "event_type": ev.event_type,
                "severity": ev.severity,
                "timestamp_utc": ev.timestamp_utc or "",
                "latitude": float(ev.latitude) if ev.latitude is not None else 0.0,
                "longitude": float(ev.longitude) if ev.longitude is not None else 0.0,
                "altitude_m": float(ev.altitude_m) if ev.altitude_m is not None else 0.0,
            }
        })
    return chunks


def chunk_geofence_violations(violations: List[GeofenceViolation], case_id: str) -> List[Dict[str, Any]]:
    chunks = []
    for vio in violations:
        text = (
            f"[GEOFENCE_VIOLATION] Zone: '{vio.zone_name}' (ID: {vio.zone_id}) | "
            f"Breach Type: {vio.violation_type} | Severity: {vio.severity} | "
            f"Timestamp (UTC): {vio.timestamp_utc} | "
            f"Breach Coordinates: lat={vio.latitude:.6f}, lon={vio.longitude:.6f}, alt={vio.altitude_m:.1f}m | "
            f"Jurisdiction Authority: {vio.authority or 'DGCA / Local Civil Aviation'} | "
            f"Airspace Category: {vio.category or 'RESTRICTED'} | Details: {vio.details}"
        )
        chunks.append({
            "text": text,
            "metadata": {
                "case_id": case_id,
                "chunk_type": "geofence_violation",
                "zone_id": vio.zone_id,
                "zone_name": vio.zone_name,
                "violation_type": vio.violation_type,
                "severity": vio.severity,
                "timestamp_utc": vio.timestamp_utc or "",
                "latitude": float(vio.latitude),
                "longitude": float(vio.longitude),
                "altitude_m": float(vio.altitude_m),
            }
        })
    return chunks


def chunk_anomalies(anomalies: List[AnomalyReport], case_id: str) -> List[Dict[str, Any]]:
    chunks = []
    for anom in anomalies:
        text = (
            f"[ANOMALY_DETECTION] Type: {anom.anomaly_type} | Severity: {anom.severity} | "
            f"Timestamp (UTC): {anom.timestamp_utc or 'N/A'} | "
            f"Evidence Reference: {anom.evidence_ref or 'Flight Log'} | "
            f"Description: {anom.description}"
        )
        if anom.details:
            details_str = ", ".join(f"{k}={v}" for k, v in list(anom.details.items())[:6])
            text += f" | Forensic Metrics: {details_str}"

        chunks.append({
            "text": text,
            "metadata": {
                "case_id": case_id,
                "chunk_type": "anomaly_report",
                "anomaly_type": anom.anomaly_type,
                "severity": anom.severity,
                "timestamp_utc": anom.timestamp_utc or "",
                "evidence_ref": anom.evidence_ref or "",
            }
        })
    return chunks


def chunk_telemetry_windows(telemetry: List[TelemetryPoint], case_id: str, window_size: int = 30) -> List[Dict[str, Any]]:
    """
    Condenses high-frequency telemetry into sliding temporal windows to optimize RAG token efficiency
    while capturing speed, altitude envelope, attitude, and battery draw.
    """
    if not telemetry:
        return []

    chunks = []
    total = len(telemetry)
    step = max(1, window_size // 2)

    for i in range(0, total, step):
        window = telemetry[i:i + window_size]
        if not window:
            continue

        start_pt = window[0]
        end_pt = window[-1]

        alts = [p.altitude_m for p in window]
        speeds = [p.ground_speed_mps for p in window]
        batteries = [p.battery_pct for p in window if p.battery_pct is not None]

        min_alt, max_alt = min(alts), max(alts)
        avg_spd, max_spd = sum(speeds) / len(speeds), max(speeds)
        batt_str = f"Batt: {min(batteries):.1f}% - {max(batteries):.1f}%" if batteries else "Batt: N/A"

        text = (
            f"[TELEMETRY_WINDOW] Time: {start_pt.timestamp_utc} to {end_pt.timestamp_utc} ({len(window)} samples) | "
            f"Start Location: lat={start_pt.latitude:.6f}, lon={start_pt.longitude:.6f}, alt={start_pt.altitude_m:.1f}m | "
            f"End Location: lat={end_pt.latitude:.6f}, lon={end_pt.longitude:.6f}, alt={end_pt.altitude_m:.1f}m | "
            f"Altitude Range: {min_alt:.1f}m to {max_alt:.1f}m | Max Speed: {max_spd:.1f} m/s (avg {avg_spd:.1f} m/s) | "
            f"{batt_str} | Source: {start_pt.source_channel}"
        )

        chunks.append({
            "text": text,
            "metadata": {
                "case_id": case_id,
                "chunk_type": "telemetry_window",
                "start_time_utc": start_pt.timestamp_utc,
                "end_time_utc": end_pt.timestamp_utc,
                "min_altitude_m": float(min_alt),
                "max_altitude_m": float(max_alt),
                "max_speed_mps": float(max_spd),
                "samples_count": len(window),
            }
        })
        if i + window_size >= total:
            break

    return chunks


def chunk_audit_log(audit_log: List[AuditLogEntry], case_id: str) -> List[Dict[str, Any]]:
    chunks = []
    for entry in audit_log:
        text = (
            f"[CHAIN_OF_CUSTODY] Sequence #{entry.entry_id} | Actor: {entry.actor} | Action: {entry.action} | "
            f"Timestamp (UTC): {entry.timestamp_utc} | Details: {entry.details} | "
            f"Evidence Item: {entry.evidence_item_id or 'Case Vault'} | HMAC Signature: {entry.signature[:16]}..."
        )
        chunks.append({
            "text": text,
            "metadata": {
                "case_id": case_id,
                "chunk_type": "audit_log",
                "entry_id": entry.entry_id,
                "actor": entry.actor,
                "action": entry.action,
                "timestamp_utc": entry.timestamp_utc,
            }
        })
    return chunks


def chunk_evidence_items(evidence: List[EvidenceItem], case_id: str) -> List[Dict[str, Any]]:
    chunks = []
    for item in evidence:
        text = (
            f"[EVIDENCE_ITEM] File: {item.file_name} (Item ID: {item.item_id}) | "
            f"Platform: {item.drone_platform or 'UNKNOWN'} | Category: {item.evidence_category} | "
            f"Acquisition: {item.acquisition_type} | Size: {item.file_size_bytes} bytes | "
            f"Write-Block Verified: {item.write_block_verified} | "
            f"SHA-256: {item.hashes.sha256} | SHA3-256: {item.hashes.sha3_256} | "
            f"Acquired At: {item.created_at}"
        )
        chunks.append({
            "text": text,
            "metadata": {
                "case_id": case_id,
                "chunk_type": "evidence_item",
                "item_id": item.item_id,
                "file_name": item.file_name,
                "drone_platform": item.drone_platform or "UNKNOWN",
                "evidence_category": item.evidence_category,
                "sha256": item.hashes.sha256,
            }
        })
    return chunks


def chunk_media_captures(media: List[MediaCapture], case_id: str) -> List[Dict[str, Any]]:
    chunks = []
    for m in media:
        coords_str = f"lat={m.matched_latitude:.6f}, lon={m.matched_longitude:.6f}, alt={m.matched_altitude_m:.1f}m" if m.matched_latitude is not None else "spatial match=PENDING"
        text = (
            f"[MEDIA_RECORD] Type: {m.media_type} | File: {m.file_name} | "
            f"Capture Timestamp: {m.capture_timestamp_utc or 'UNKNOWN'} | "
            f"Telemetry Overlap: {m.has_telemetry_overlap} | Geo-Coordinates: {coords_str} | "
            f"SHA-256: {m.hashes.sha256} | E01 Forensically Sealed: {m.has_e01}"
        )
        chunks.append({
            "text": text,
            "metadata": {
                "case_id": case_id,
                "chunk_type": "media_capture",
                "file_name": m.file_name,
                "media_type": m.media_type,
                "has_telemetry_overlap": m.has_telemetry_overlap,
                "capture_timestamp_utc": m.capture_timestamp_utc or "",
            }
        })
    return chunks


def chunk_gcs_data(gcs: Optional[GCSAnalysisResult], case_id: str) -> List[Dict[str, Any]]:
    if not gcs:
        return []
    chunks = []
    text = (
        f"[GCS_ANALYSIS] Ground Control Station: {gcs.detected_gcs} | Flight Controller: {gcs.associated_fc} | "
        f"Artifacts Found: {len(gcs.gcs_artifacts)} files | Mission Plans: {len(gcs.mission_plans)} | "
        f"Commands Issued: {len(gcs.commands_issued)}"
    )
    chunks.append({
        "text": text,
        "metadata": {
            "case_id": case_id,
            "chunk_type": "gcs_overview",
            "detected_gcs": gcs.detected_gcs,
        }
    })

    for op in gcs.operator_locations:
        op_text = (
            f"[OPERATOR_LOCATION] Source: {op.source} | Coordinates: lat={op.latitude:.6f}, lon={op.longitude:.6f}, alt={op.altitude_m or 0.0:.1f}m | "
            f"Timestamp (UTC): {op.timestamp_utc or 'N/A'} | Accuracy: {op.accuracy_m or 0.0:.1f}m | Description: {op.description}"
        )
        chunks.append({
            "text": op_text,
            "metadata": {
                "case_id": case_id,
                "chunk_type": "operator_location",
                "source": op.source,
                "latitude": float(op.latitude),
                "longitude": float(op.longitude),
            }
        })

    for plan in gcs.mission_plans:
        plan_text = (
            f"[MISSION_PLAN] Plan ID: {plan.plan_id} | Target GCS: {plan.gcs_name} | File: {plan.file_name} | "
            f"Waypoints Count: {len(plan.waypoints)} | Total Planned Distance: {plan.total_planned_distance_m:.1f}m | "
            f"Max Altitude: {plan.planned_max_altitude_m:.1f}m | Geofence Included: {plan.geofence_included}"
        )
        chunks.append({
            "text": plan_text,
            "metadata": {
                "case_id": case_id,
                "chunk_type": "mission_plan",
                "plan_id": plan.plan_id,
                "gcs_name": plan.gcs_name,
            }
        })

    return chunks


def chunk_mobile_artifacts(mobile: Optional[MobileCompanionAnalysisResult], case_id: str) -> List[Dict[str, Any]]:
    if not mobile:
        return []
    chunks = []
    overview = (
        f"[MOBILE_COMPANION] Companion Apps Detected: {', '.join(mobile.apps_detected) or 'None'} | "
        f"Platforms: {', '.join(mobile.platforms_involved) or 'N/A'} | Total Flight Records: {mobile.total_flight_records} | "
        f"Waypoints Recovered: {mobile.total_waypoints_recovered} | Operator Fixes: {len(mobile.operator_locations)}"
    )
    chunks.append({
        "text": overview,
        "metadata": {
            "case_id": case_id,
            "chunk_type": "mobile_overview",
        }
    })

    for art in mobile.artifacts:
        pilot_info = ""
        if art.pilot_account:
            pilot_info = ", ".join(f"{k}={v}" for k, v in art.pilot_account.items() if v)
        hw_info = ""
        if art.paired_hardware:
            hw_info = ", ".join(f"{k}={v}" for k, v in art.paired_hardware.items() if v)

        art_text = (
            f"[MOBILE_APP_ARTIFACT] App: {art.app_name} ({art.package_id or 'unknown package'}) | "
            f"Platform: {art.target_platform} | Pilot Account: {pilot_info or 'Unregistered/Anonymous'} | "
            f"Paired Hardware: {hw_info or 'None'} | Flight Logs Cached: {len(art.flight_logs)}"
        )
        chunks.append({
            "text": art_text,
            "metadata": {
                "case_id": case_id,
                "chunk_type": "mobile_app_artifact",
                "app_name": art.app_name,
                "target_platform": art.target_platform,
            }
        })

    for op in mobile.operator_locations:
        op_text = (
            f"[MOBILE_OPERATOR_FIX] Source: {op.source} | Coordinates: lat={op.latitude:.6f}, lon={op.longitude:.6f} | "
            f"Timestamp (UTC): {op.timestamp_utc or 'N/A'} | Accuracy: {op.accuracy_m or 0.0:.1f}m | Description: {op.description}"
        )
        chunks.append({
            "text": op_text,
            "metadata": {
                "case_id": case_id,
                "chunk_type": "mobile_operator_fix",
                "source": op.source,
                "latitude": float(op.latitude),
                "longitude": float(op.longitude),
            }
        })

    return chunks

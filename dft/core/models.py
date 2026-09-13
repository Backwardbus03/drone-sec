"""
Unified forensic models and schemas for Drone Forensic Toolkit.
"""

from datetime import datetime, timezone
from typing import List, Optional, Dict, Any, Literal
from pydantic import BaseModel, Field


class CaseMetadata(BaseModel):
    case_id: str
    case_name: str
    investigator_name: str
    agency_name: str
    description: Optional[str] = ""
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: Literal["OPEN", "IN_PROGRESS", "CLOSED"] = "OPEN"


class HashManifest(BaseModel):
    sha256: str
    sha3_256: str
    md5: str
    byte_count: int
    computed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class EvidenceItem(BaseModel):
    item_id: str
    case_id: str
    file_name: str
    source_path: str
    file_size_bytes: int
    hashes: HashManifest
    acquisition_type: Literal["PHYSICAL_IMAGE", "LOGICAL_EXTRACT", "NETWORK_PCAP", "MANUAL_IMPORT"]
    write_block_verified: bool = True
    drone_platform: Optional[str] = "UNKNOWN"
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class TelemetryPoint(BaseModel):
    timestamp_utc: str
    latitude: float
    longitude: float
    altitude_m: float
    ground_speed_mps: float = 0.0
    pitch_deg: float = 0.0
    roll_deg: float = 0.0
    yaw_deg: float = 0.0
    battery_pct: Optional[float] = None
    satellites_visible: Optional[int] = None
    source_channel: str = "FC_LOG"


class FlightEvent(BaseModel):
    event_id: str
    timestamp_utc: str
    event_type: Literal[
        "POWER_ON",
        "GPS_LOCK",
        "ARM",
        "DISARM",
        "TAKEOFF",
        "LANDING",
        "WAYPOINT_REACHED",
        "MEDIA_CAPTURE",
        "GEOFENCE_BREACH",
        "SIGNAL_LOSS",
        "FAILSAFE",
        "RETURN_TO_HOME",
        "ERROR_ALERT"
    ]
    severity: Literal["INFO", "WARNING", "CRITICAL"] = "INFO"
    description: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    altitude_m: Optional[float] = None
    raw_payload: Optional[Dict[str, Any]] = None


class GeofenceZone(BaseModel):
    zone_id: str
    name: str
    zone_type: Literal["polygon", "circle"] = "polygon"
    # For polygon: list of [lat, lon] points. For circle: single center or center_lat/center_lon
    coordinates: List[List[float]] = []
    center_lat: Optional[float] = None
    center_lon: Optional[float] = None
    radius_meters: Optional[float] = None
    max_altitude_m: Optional[float] = None
    min_altitude_m: Optional[float] = None
    active_from_utc: Optional[str] = None
    active_to_utc: Optional[str] = None
    description: Optional[str] = None
    is_preconfigured_nofly: bool = False
    category: Optional[str] = "CUSTOM"  # "AIRPORT", "AIRDROME", "MILITARY_AIRFORCE", "GOVERNMENT", "STRATEGIC_NUCLEAR", "PRISON", "CONTROLLED_BUFFER", "CUSTOM"
    zone_class: Optional[str] = "RED"   # "RED" (0m ceiling/absolute no-fly), "YELLOW" (controlled/altitude cap), "GREEN"
    authority: Optional[str] = None     # e.g., "DGCA / AAI", "Ministry of Defence", "Ministry of Home Affairs", "FAA"
    city_region: Optional[str] = None   # e.g., "Mumbai / MMR", "Delhi NCR", "Bengaluru", "National / Global"


class GeofenceViolation(BaseModel):
    violation_id: str
    zone_id: str
    zone_name: str
    timestamp_utc: str
    latitude: float
    longitude: float
    altitude_m: float
    violation_type: Literal["BOUNDARY_ENTRY", "CEILING_EXCEEDED", "FLOOR_BREACHED", "TIME_WINDOW_BREACH"]
    severity: Literal["WARNING", "CRITICAL"] = "CRITICAL"
    details: str
    category: Optional[str] = None
    authority: Optional[str] = None


class AnomalyReport(BaseModel):
    anomaly_id: str
    anomaly_type: Literal[
        "TIMESTAMP_GAP",
        "CLOCK_SKEW",
        "GPS_DISCORDANCE",
        "BATTERY_VOLTAGE_DROP",
        "UNEXPECTED_DISARM",
        "CHECKSUM_MISMATCH",
        "CORRUPTED_RECORD"
    ]
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    description: str
    timestamp_utc: Optional[str] = None
    evidence_ref: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class AuditLogEntry(BaseModel):
    entry_id: int
    case_id: str
    timestamp_utc: str
    actor: str
    action: str
    details: str
    evidence_item_id: Optional[str] = None
    previous_hash: str
    signature: str


class FlightSummary(BaseModel):
    platform_detected: str
    total_duration_sec: float
    total_distance_meters: float
    max_altitude_m: float
    max_speed_mps: float
    start_time_utc: Optional[str] = None
    end_time_utc: Optional[str] = None
    arm_time_utc: Optional[str] = None
    disarm_time_utc: Optional[str] = None
    telemetry_count: int
    events_count: int
    violations_count: int
    anomalies_count: int

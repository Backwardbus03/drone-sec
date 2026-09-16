"""
Investigator-Configurable Geofence Analysis Engine.
Implements Ray-Casting Point-in-Polygon, Haversine circular proximity,
altitude boundary checks, and temporal window verification.
"""

import math
from datetime import datetime
from typing import List, Tuple, Optional, Dict, Any
from dft.core.models import GeofenceZone, GeofenceViolation, TelemetryPoint
from dft.analysis.restricted_spaces import (
    get_default_core_presets,
    get_all_restricted_spaces,
    get_catalog_filtered,
    get_preset_by_id
)


def haversine_distance_meters(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculates spherical distance between two geographic coordinates in meters."""
    R = 6371000.0  # Earth radius in meters
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = math.sin(delta_phi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return R * c


def haversine_distance_vectorized(lats1: Any, lons1: Any, lat2: float, lon2: float) -> Any:
    """Calculates spherical distance between arrays of coordinates and a target coordinate in meters."""
    import numpy as np
    R = 6371000.0
    phi1 = np.radians(lats1)
    phi2 = np.radians(lat2)
    delta_phi = phi2 - phi1
    delta_lambda = np.radians(lon2) - np.radians(lons1)

    a = np.sin(delta_phi / 2.0) ** 2 + np.cos(phi1) * np.cos(phi2) * np.sin(delta_lambda / 2.0) ** 2
    c = 2.0 * np.arctan2(np.sqrt(a), np.sqrt(np.maximum(0.0, 1.0 - a)))
    return R * c


def haversine_distance_pairwise_vectorized(lats1: Any, lons1: Any, lats2: Any, lons2: Any) -> Any:
    """Calculates spherical distance between pairwise coordinates in meters."""
    import numpy as np
    R = 6371000.0
    phi1 = np.radians(lats1)
    phi2 = np.radians(lats2)
    delta_phi = phi2 - phi1
    delta_lambda = np.radians(lons2) - np.radians(lons1)

    a = np.sin(delta_phi / 2.0) ** 2 + np.cos(phi1) * np.cos(phi2) * np.sin(delta_lambda / 2.0) ** 2
    c = 2.0 * np.arctan2(np.sqrt(a), np.sqrt(np.maximum(0.0, 1.0 - a)))
    return R * c


def point_in_polygon(lat: float, lon: float, polygon: List[List[float]]) -> bool:
    """
    Ray-Casting Algorithm for Point-in-Polygon test.
    Polygon is a list of [lat, lon] vertices.
    """
    if len(polygon) < 3:
        return False

    inside = False
    n = len(polygon)
    j = n - 1

    for i in range(n):
        lat_i, lon_i = polygon[i][0], polygon[i][1]
        lat_j, lon_j = polygon[j][0], polygon[j][1]

        # Check if horizontal ray crosses edge
        if ((lon_i > lon) != (lon_j > lon)) and \
           (lat < (lat_j - lat_i) * (lon - lon_i) / (lon_j - lon_i + 1e-12) + lat_i):
            inside = not inside
        j = i

    return inside


class GeofenceEngine:
    def __init__(self, zones: List[GeofenceZone] = None):
        self.zones: List[GeofenceZone] = zones if zones is not None else self._get_default_presets()

    def add_zone(self, zone: GeofenceZone):
        # Prevent duplicate zone IDs
        self.zones = [z for z in self.zones if z.zone_id != zone.zone_id]
        self.zones.append(zone)

    def import_preset(self, preset_id: str) -> Optional[GeofenceZone]:
        """Imports a real-world restricted space preset by ID into the active zone list."""
        preset = get_preset_by_id(preset_id)
        if preset:
            self.add_zone(preset)
            return preset
        return None

    def load_all_presets(self) -> int:
        """Loads all real-world restricted airspaces from catalog into active zones."""
        all_spaces = get_all_restricted_spaces()
        existing_ids = {z.zone_id for z in self.zones}
        added_count = 0
        for space in all_spaces:
            if space.zone_id not in existing_ids:
                self.zones.append(space)
                existing_ids.add(space.zone_id)
                added_count += 1
        return added_count

    def _get_default_presets(self) -> List[GeofenceZone]:
        """Provides real-world default restricted airspaces (airports, aerodromes, government, nuclear, controlled buffers)."""
        return get_default_core_presets()

    def evaluate_telemetry(self, telemetry: List[TelemetryPoint]) -> List[GeofenceViolation]:
        """
        Scans entire flight telemetry sequence against all active geofence zones.
        Detects boundary entry, altitude ceilings, and temporal breaches.
        Uses NumPy vectorization for massive speedup over large telemetry tracks.
        """
        if not telemetry:
            return []

        violations: List[GeofenceViolation] = []
        violation_counter = 1

        import numpy as np
        lats = np.array([pt.latitude for pt in telemetry], dtype=np.float64)
        lons = np.array([pt.longitude for pt in telemetry], dtype=np.float64)

        # Map pt_index -> list of matching zones
        zone_matches: Dict[int, List[GeofenceZone]] = {}

        for zone in self.zones:
            matching_indices = []

            # 1. Spatial Boundary Check (Vectorized)
            if zone.zone_type == "circle" and zone.center_lat is not None and zone.center_lon is not None and zone.radius_meters:
                dists = haversine_distance_vectorized(lats, lons, zone.center_lat, zone.center_lon)
                matching_indices = np.where(dists <= zone.radius_meters)[0]
            elif zone.zone_type == "polygon" and zone.coordinates and len(zone.coordinates) >= 3:
                # Fast bounding box pre-filter with NumPy
                min_lat = min(v[0] for v in zone.coordinates)
                max_lat = max(v[0] for v in zone.coordinates)
                min_lon = min(v[1] for v in zone.coordinates)
                max_lon = max(v[1] for v in zone.coordinates)
                candidates = np.where((lats >= min_lat) & (lats <= max_lat) & (lons >= min_lon) & (lons <= max_lon))[0]
                if len(candidates) > 0:
                    for idx in candidates:
                        if point_in_polygon(lats[idx], lons[idx], zone.coordinates):
                            matching_indices.append(idx)

            for idx in matching_indices:
                zone_matches.setdefault(int(idx), []).append(zone)

        if not zone_matches:
            return []

        # Process violations in chronological order
        for idx in sorted(zone_matches.keys()):
            pt = telemetry[idx]
            for zone in zone_matches[idx]:
                # 2. Time Window Check (if configured)
                in_time_window = True
                if zone.active_from_utc or zone.active_to_utc:
                    try:
                        pt_time = datetime.fromisoformat(pt.timestamp_utc.replace("Z", "+00:00"))
                        if zone.active_from_utc:
                            t_start = datetime.fromisoformat(zone.active_from_utc.replace("Z", "+00:00"))
                            if pt_time < t_start:
                                in_time_window = False
                        if zone.active_to_utc:
                            t_end = datetime.fromisoformat(zone.active_to_utc.replace("Z", "+00:00"))
                            if pt_time > t_end:
                                in_time_window = False
                    except Exception:
                        pass

                # 3. Altitude Checks
                if in_time_window:
                    breach_type = "BOUNDARY_ENTRY"
                    auth_prefix = f" [{zone.authority}]" if zone.authority else ""
                    details = f"UAV entered restricted airspace '{zone.name}'{auth_prefix} at altitude {pt.altitude_m:.1f}m"

                    if zone.max_altitude_m is not None and pt.altitude_m > zone.max_altitude_m:
                        breach_type = "CEILING_EXCEEDED"
                        details = f"UAV exceeded statutory ceiling ({zone.max_altitude_m}m) inside '{zone.name}'{auth_prefix} at altitude {pt.altitude_m:.1f}m"

                    violations.append(GeofenceViolation(
                        violation_id=f"VIO-{violation_counter:04d}",
                        zone_id=zone.zone_id,
                        zone_name=zone.name,
                        timestamp_utc=pt.timestamp_utc,
                        latitude=pt.latitude,
                        longitude=pt.longitude,
                        altitude_m=pt.altitude_m,
                        violation_type=breach_type,
                        severity="CRITICAL" if zone.is_preconfigured_nofly or zone.zone_class == "RED" else "WARNING",
                        details=details,
                        category=zone.category,
                        authority=zone.authority
                    ))
                    violation_counter += 1

        return violations

"""
Base abstract plugin class for Drone Forensic Toolkit.
All platform parsers (DJI, ArduPilot, PX4, Parrot, Betaflight) inherit from this interface.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
from dft.core.models import TelemetryPoint, FlightEvent


class DroneForensicPlugin(ABC):
    def __init__(self):
        self._cached_path: Optional[str] = None
        self._cached_data: Optional[Tuple[List[TelemetryPoint], List[FlightEvent], Dict[str, Any]]] = None

    @property
    @abstractmethod
    def platform_id(self) -> str:
        """Machine identifier (e.g. 'dji', 'ardupilot', 'px4', 'parrot', 'betaflight')."""
        pass

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human-readable platform name."""
        pass

    @property
    @abstractmethod
    def supported_extensions(self) -> List[str]:
        """List of file extensions recognized by this parser."""
        pass

    @abstractmethod
    def detect(self, file_path: Path) -> bool:
        """
        Returns True if the file matches this drone platform's signature or structure.
        """
        pass

    def parse_all(self, file_path: Path) -> Tuple[List[TelemetryPoint], List[FlightEvent], Dict[str, Any]]:
        """
        Single-pass parser extracting telemetry, events, and metadata simultaneously.
        Override this method in plugins to eliminate redundant file I/O and passes.
        """
        telemetry = self.parse_telemetry(file_path)
        events = self.parse_events(file_path)
        metadata = self.extract_metadata(file_path)
        return telemetry, events, metadata

    def _get_cached_or_parse(self, file_path: Path) -> Tuple[List[TelemetryPoint], List[FlightEvent], Dict[str, Any]]:
        key = str(file_path.resolve())
        if self._cached_path == key and self._cached_data is not None:
            return self._cached_data
        result = self.parse_all(file_path)
        self._cached_path = key
        self._cached_data = result
        return result

    def parse_telemetry(self, file_path: Path) -> List[TelemetryPoint]:
        """
        Extracts synchronized, normalized GPS & flight telemetry points.
        """
        return self._get_cached_or_parse(file_path)[0]

    def parse_events(self, file_path: Path) -> List[FlightEvent]:
        """
        Extracts discrete flight events (arm, disarm, failsafe, waypoints, media).
        """
        return self._get_cached_or_parse(file_path)[1]

    def extract_metadata(self, file_path: Path) -> Dict[str, Any]:
        """
        Extracts flight controller serial, firmware version, drone model, sensor configs.
        """
        return self._get_cached_or_parse(file_path)[2]


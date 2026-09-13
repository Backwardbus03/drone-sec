"""
Base abstract plugin class for Drone Forensic Toolkit.
All platform parsers (DJI, ArduPilot, PX4, Parrot, Betaflight) inherit from this interface.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict, Any
from dft.core.models import TelemetryPoint, FlightEvent


class DroneForensicPlugin(ABC):
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

    @abstractmethod
    def parse_telemetry(self, file_path: Path) -> List[TelemetryPoint]:
        """
        Extracts synchronized, normalized GPS & flight telemetry points.
        """
        pass

    @abstractmethod
    def parse_events(self, file_path: Path) -> List[FlightEvent]:
        """
        Extracts discrete flight events (arm, disarm, failsafe, waypoints, media).
        """
        pass

    @abstractmethod
    def extract_metadata(self, file_path: Path) -> Dict[str, Any]:
        """
        Extracts flight controller serial, firmware version, drone model, sensor configs.
        """
        pass

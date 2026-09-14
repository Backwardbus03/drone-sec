"""
Plugin Manager for Drone Forensic Toolkit.
Provides dynamic registry, signature detection, and multi-format parsing.
"""

from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any
from dft.plugins.base import DroneForensicPlugin
from dft.plugins.dji import DJIPlugin
from dft.plugins.ardupilot import ArduPilotPlugin
from dft.plugins.px4 import PX4Plugin
from dft.plugins.parrot import ParrotPlugin
from dft.plugins.betaflight import BetaflightPlugin
from dft.core.models import TelemetryPoint, FlightEvent


class PluginManager:
    def __init__(self):
        self._plugins: List[DroneForensicPlugin] = [
            DJIPlugin(),
            ArduPilotPlugin(),
            PX4Plugin(),
            ParrotPlugin(),
            BetaflightPlugin()
        ]

    def register_plugin(self, plugin: DroneForensicPlugin):
        """Allows dynamic drop-in registration of new platform plugins."""
        self._plugins.append(plugin)

    def list_plugins(self) -> List[Dict[str, Any]]:
        return [
            {
                "platform_id": p.platform_id,
                "display_name": p.display_name,
                "supported_extensions": p.supported_extensions
            }
            for p in self._plugins
        ]

    def detect_platform(self, file_path: Path) -> Optional[DroneForensicPlugin]:
        """
        Evaluates evidence against all registered plugins and returns the matching parser.
        """
        for plugin in self._plugins:
            try:
                if plugin.detect(file_path):
                    return plugin
            except Exception:
                continue
        return None

    def parse_evidence(self, file_path: Path) -> Tuple[str, List[TelemetryPoint], List[FlightEvent], Dict[str, Any]]:
        """
        Parses evidence file and returns (platform_id, telemetry_points, events, metadata).
        """
        plugin = self.detect_platform(file_path)
        if not plugin:
            # Fallback heuristic based on extension
            ext = file_path.suffix.lower()
            if ext in [".dat", ".srt", ".kmz", ".kml"]:
                plugin = DJIPlugin()
            elif ext in [".bin", ".tlog", ".param", ".parm", ".waypoints"]:
                plugin = ArduPilotPlugin()
            elif ext in [".ulg", ".plan"]:
                plugin = PX4Plugin()
            elif ext in [".pud", ".mavlink"]:
                plugin = ParrotPlugin()
            elif ext in [".bbl", ".mission", ".mwp"]:
                plugin = BetaflightPlugin()
            else:
                plugin = DJIPlugin()  # Default fallback

        telemetry = plugin.parse_telemetry(file_path)
        events = plugin.parse_events(file_path)
        metadata = plugin.extract_metadata(file_path)

        return plugin.platform_id, telemetry, events, metadata

from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any
from dft.plugins.base import DroneForensicPlugin
from dft.plugins.dji import DJIPlugin
from dft.plugins.ardupilot import ArduPilotPlugin
from dft.plugins.px4 import PX4Plugin
from dft.plugins.parrot import ParrotPlugin
from dft.plugins.betaflight import BetaflightPlugin
from dft.core.models import TelemetryPoint, FlightEvent


def _worker_parse_single_file(file_path_str: str) -> Tuple[str, List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """Standalone worker for ProcessPoolExecutor serialization."""
    path = Path(file_path_str)
    mgr = PluginManager()
    plat_id, telemetry, events, meta = mgr.parse_evidence(path)
    return (
        plat_id,
        [p.model_dump() for p in telemetry],
        [e.model_dump() for e in events],
        meta
    )


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
        Parses evidence file in a single pass and returns (platform_id, telemetry_points, events, metadata).
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

        telemetry, events, metadata = plugin.parse_all(file_path)
        return plugin.platform_id, telemetry, events, metadata

    def batch_parse_evidence(
        self, file_paths: List[Path], max_workers: Optional[int] = None
    ) -> List[Tuple[str, List[TelemetryPoint], List[FlightEvent], Dict[str, Any]]]:
        """
        Parallelized ingestion across multiple evidence files using ProcessPoolExecutor.
        Scales CPU-bound parser workloads across cores.
        """
        if not file_paths:
            return []

        if len(file_paths) == 1:
            return [self.parse_evidence(file_paths[0])]

        results: List[Tuple[str, List[TelemetryPoint], List[FlightEvent], Dict[str, Any]]] = []
        path_strs = [str(p.resolve()) for p in file_paths]

        try:
            from concurrent.futures import ProcessPoolExecutor
            with ProcessPoolExecutor(max_workers=max_workers) as executor:
                raw_results = list(executor.map(_worker_parse_single_file, path_strs))

            for plat_id, tel_dicts, ev_dicts, meta in raw_results:
                telemetry = [TelemetryPoint(**td) for td in tel_dicts]
                events = [FlightEvent(**ed) for ed in ev_dicts]
                results.append((plat_id, telemetry, events, meta))
        except Exception:
            # Fallback to sequential execution if multiprocessing context fails
            for p in file_paths:
                results.append(self.parse_evidence(p))

        return results


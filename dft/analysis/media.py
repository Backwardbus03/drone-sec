"""
Drone Media & EXIF Forensic Extractor.
Parses EXIF, GPS IFD, and XMP metadata from UAV aerial photographs (JPEG, TIFF, DNG)
and video subtitle telemetry (.srt) compliant with ISO/IEC 27037:2012.
"""

from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timezone
import re
import PIL.Image
import PIL.ExifTags

from dft.core.models import TelemetryPoint
from dft.core.hashing import compute_hashes, HashManifest


def _convert_to_degrees(value) -> Optional[float]:
    """Helper to convert the GPS coordinates stored in EXIF to degrees in float format."""
    try:
        if isinstance(value, (int, float)):
            return float(value)
        # Handle rational tuple (deg, min, sec)
        d0 = float(value[0])
        d1 = float(value[1])
        d2 = float(value[2])
        return d0 + (d1 / 60.0) + (d2 / 3600.0)
    except Exception:
        return None


class DroneMediaExtractor:
    """Forensic metadata extractor for drone aerial images and video assets."""

    @staticmethod
    def extract_image_metadata(image_path: Path) -> Dict[str, Any]:
        """
        Extracts EXIF, GPS, camera parameters, and integrity hashes from a drone photo.
        """
        image_path = Path(image_path)
        if not image_path.exists():
            raise FileNotFoundError(f"Image file not found: {image_path}")

        manifest = compute_hashes(image_path)

        result: Dict[str, Any] = {
            "file_name": image_path.name,
            "file_size_bytes": manifest.byte_count,
            "hashes": manifest.model_dump(),
            "has_exif": False,
            "has_gps": False,
            "camera_make": "UNKNOWN",
            "camera_model": "UNKNOWN",
            "drone_software": None,
            "capture_timestamp_utc": None,
            "latitude": None,
            "longitude": None,
            "altitude_m": None,
            "gimbal_track_deg": None,
            "raw_exif": {}
        }

        try:
            with PIL.Image.open(image_path) as img:
                exif = img.getexif()
                if not exif:
                    return result

                result["has_exif"] = True

                # Top-level EXIF tags
                for tag_id, val in exif.items():
                    tag_name = PIL.ExifTags.TAGS.get(tag_id, str(tag_id))
                    if tag_name == "Make":
                        result["camera_make"] = str(val).strip()
                    elif tag_name == "Model":
                        result["camera_model"] = str(val).strip()
                    elif tag_name == "Software":
                        result["drone_software"] = str(val).strip()
                    elif tag_name == "DateTime":
                        # Standard format: YYYY:MM:DD HH:MM:SS
                        try:
                            dt = datetime.strptime(str(val).strip(), "%Y:%m:%d %H:%M:%S")
                            result["capture_timestamp_utc"] = dt.replace(tzinfo=timezone.utc).isoformat()
                        except Exception:
                            result["capture_timestamp_utc"] = str(val).strip()

                # GPS IFD tags
                gps_ifd = exif.get_ifd(PIL.ExifTags.IFD.GPSInfo)
                if gps_ifd:
                    gps_dict = {PIL.ExifTags.GPSTAGS.get(k, str(k)): v for k, v in gps_ifd.items()}
                    lat = _convert_to_degrees(gps_dict.get("GPSLatitude"))
                    lat_ref = gps_dict.get("GPSLatitudeRef", "N")
                    if lat is not None and lat_ref == "S":
                        lat = -lat

                    lon = _convert_to_degrees(gps_dict.get("GPSLongitude"))
                    lon_ref = gps_dict.get("GPSLongitudeRef", "E")
                    if lon is not None and lon_ref == "W":
                        lon = -lon

                    alt = gps_dict.get("GPSAltitude")
                    if alt is not None:
                        try:
                            alt = float(alt)
                        except Exception:
                            alt = None

                    track = gps_dict.get("GPSTrack")
                    if track is not None:
                        try:
                            track = float(track)
                        except Exception:
                            track = None

                    if lat is not None and lon is not None:
                        result["has_gps"] = True
                        result["latitude"] = round(lat, 7)
                        result["longitude"] = round(lon, 7)
                        result["altitude_m"] = round(alt, 2) if alt is not None else 0.0
                        result["gimbal_track_deg"] = round(track, 1) if track is not None else None

        except Exception as e:
            result["extraction_error"] = str(e)

        return result

    # Alias for convenience
    extract_photo_metadata = extract_image_metadata

    @staticmethod
    def extract_video_telemetry(srt_path: Path) -> List[TelemetryPoint]:
        """Parses companion video subtitle files (.srt) for frame-level telemetry."""
        from dft.plugins.dji import DJIPlugin
        return DJIPlugin()._parse_srt(Path(srt_path))

    @staticmethod
    def extract_video_subtitle_telemetry(srt_path: Path) -> List[Dict[str, Any]]:
        """
        Parses frame-by-frame telemetry from drone video subtitle (.srt) files,
        supporting both bracketed format and Phantom/Mavic HOME/GPS formatted streams.
        """
        srt_path = Path(srt_path)
        if not srt_path.exists():
            return []

        entries: List[Dict[str, Any]] = []
        try:
            with open(srt_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            blocks = content.strip().split("\n\n")
            for block in blocks:
                lines = [line.strip() for line in block.splitlines() if line.strip()]
                if len(lines) < 2:
                    continue

                frame_idx = None
                try:
                    frame_idx = int(lines[0])
                except ValueError:
                    pass

                lat = None
                lon = None
                alt = 0.0

                gps_paren = re.search(r"GPS\s*\(\s*([+-]?\d+\.\d+)\s*,\s*([+-]?\d+\.\d+)(?:\s*,\s*(\d+))?\s*\)", block, re.IGNORECASE)
                if gps_paren:
                    v1 = float(gps_paren.group(1))
                    v2 = float(gps_paren.group(2))
                    if abs(v1) > 90 or (abs(v2) <= 90 and abs(v1) > abs(v2)):
                        lon, lat = v1, v2
                    else:
                        lat, lon = v1, v2
                else:
                    lat_m = re.search(r"(?:latitude|lat)[:\s]+([+-]?\d+\.\d+)", block, re.IGNORECASE)
                    lon_m = re.search(r"(?:longitude|lon)[:\s]+([+-]?\d+\.\d+)", block, re.IGNORECASE)
                    if lat_m and lon_m:
                        lat = float(lat_m.group(1))
                        lon = float(lon_m.group(1))

                baro_m = re.search(r"(?:BAROMETER|altitude|alt|rel_alt)[:\s]+([+-]?\d+(?:\.\d+)?)\s*M?", block, re.IGNORECASE)
                if baro_m:
                    try:
                        alt = float(baro_m.group(1))
                    except ValueError:
                        alt = 0.0

                iso_m = re.search(r"ISO[:\s]+(\d+)", block, re.IGNORECASE)
                shutter_m = re.search(r"Shutter[:\s]+([^\s]+)", block, re.IGNORECASE)
                fnum_m = re.search(r"Fnum[:\s]+([^\s]+)", block, re.IGNORECASE)

                if lat is not None and lon is not None:
                    entries.append({
                        "frame_index": frame_idx or (len(entries) + 1),
                        "latitude": round(lat, 7),
                        "longitude": round(lon, 7),
                        "altitude_m": round(alt, 2),
                        "camera_settings": {
                            "iso": iso_m.group(1) if iso_m else None,
                            "shutter": shutter_m.group(1) if shutter_m else None,
                            "fnum": fnum_m.group(1) if fnum_m else None
                        }
                    })
        except Exception:
            pass

        return entries


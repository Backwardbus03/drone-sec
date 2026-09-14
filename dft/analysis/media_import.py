"""
Drone Media Forensic Import & Telemetry Synchronization Module.
Supports MP4, MOV, and drone aerial photographs (JPEG, PNG, DNG, TIFF) compliant with ISO/IEC 27037:2012.
Extracts timestamps, metadata, and representative frames, and correlates capture intervals against UAV telemetry.
"""

from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple, Literal
from datetime import datetime, timezone, timedelta
import struct
import io
import base64
import uuid

import PIL.Image
import PIL.ExifTags
import cv2

try:
    from mutagen.mp4 import MP4
except ImportError:
    MP4 = None

import shutil
from dft.core.models import TelemetryPoint, FlightEvent, MediaCapture
from dft.core.hashing import compute_hashes
from dft.core.write_blocker import WriteBlockController
from dft.acquisition.e01 import E01Writer
from dft.analysis.media import DroneMediaExtractor


SUPPORTED_VIDEO_EXTENSIONS = {".mp4", ".mov", ".m4v", ".avi", ".mkv", ".webm"}
SUPPORTED_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".dng", ".bmp", ".webp"}


def detect_media_type(path: Path) -> Literal["IMAGE", "VIDEO"]:
    """Determines whether the given media file is an IMAGE or VIDEO based on extension."""
    suffix = path.suffix.lower()
    if suffix in SUPPORTED_VIDEO_EXTENSIONS:
        return "VIDEO"
    if suffix in SUPPORTED_IMAGE_EXTENSIONS:
        return "IMAGE"
    # Fallback heuristic
    return "IMAGE"


def _parse_iso_datetime(ts_str: Optional[str]) -> Optional[datetime]:
    """Helper to parse varied ISO / datetime strings to UTC datetime."""
    if not ts_str:
        return None
    cleaned = ts_str.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        pass

    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y:%m:%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            dt = datetime.strptime(cleaned, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except Exception:
            continue
    return None


def extract_video_mvhd_metadata(video_path: Path) -> Tuple[Optional[datetime], Optional[float]]:
    """
    Parses QuickTime / ISO Base Media (MP4/MOV) Movie Header Box ('mvhd') atom
    directly to retrieve standard 1904-epoch UTC creation timestamp and duration.
    """
    try:
        with open(video_path, "rb") as f:
            # Read first 512KB where moov/mvhd header usually resides
            header_chunk = f.read(524288)

        idx = header_chunk.find(b"mvhd")
        if idx == -1:
            # If not in the first 512KB, search in last 512KB (moov atom at end of file)
            file_size = video_path.stat().st_size
            if file_size > 524288:
                with open(video_path, "rb") as f:
                    f.seek(max(0, file_size - 524288))
                    header_chunk = f.read(524288)
                idx = header_chunk.find(b"mvhd")

        if idx != -1 and len(header_chunk) >= idx + 24:
            version = header_chunk[idx + 4]
            mac_epoch = datetime(1904, 1, 1, tzinfo=timezone.utc)
            if version == 0 and len(header_chunk) >= idx + 24:
                creation_time, _mod_time, timescale, duration = struct.unpack(
                    ">IIII", header_chunk[idx + 8 : idx + 24]
                )
                dt = (
                    mac_epoch + timedelta(seconds=creation_time)
                    if creation_time > 0
                    else None
                )
                dur_sec = duration / timescale if timescale > 0 else None
                return dt, dur_sec
            elif version == 1 and len(header_chunk) >= idx + 36:
                creation_time, _mod_time, timescale, duration = struct.unpack(
                    ">QQIQ", header_chunk[idx + 8 : idx + 36]
                )
                dt = (
                    mac_epoch + timedelta(seconds=creation_time)
                    if creation_time > 0
                    else None
                )
                dur_sec = duration / timescale if timescale > 0 else None
                return dt, dur_sec
    except Exception:
        pass
    return None, None


def extract_media_timestamp_and_details(
    media_path: Path, media_type: Literal["IMAGE", "VIDEO"]
) -> Tuple[Optional[datetime], Optional[float], Dict[str, Any]]:
    """
    Extracts timestamp, duration (if video), and camera/encoding metadata.
    """
    meta_details: Dict[str, Any] = {}
    timestamp: Optional[datetime] = None
    duration_sec: Optional[float] = None

    if media_type == "IMAGE":
        img_meta = DroneMediaExtractor.extract_image_metadata(media_path)
        meta_details.update(img_meta)
        if img_meta.get("capture_timestamp_utc"):
            timestamp = _parse_iso_datetime(img_meta["capture_timestamp_utc"])

    elif media_type == "VIDEO":
        # 1. First attempt atom parsing for universal MP4/MOV creation time
        mvhd_dt, mvhd_dur = extract_video_mvhd_metadata(media_path)
        if mvhd_dt:
            timestamp = mvhd_dt
        if mvhd_dur:
            duration_sec = mvhd_dur

        # 2. Mutagen metadata fallback/enrichment
        if MP4 is not None:
            try:
                mp4 = MP4(str(media_path))
                if duration_sec is None and hasattr(mp4.info, "length") and mp4.info.length > 0:
                    duration_sec = float(mp4.info.length)
                if timestamp is None and mp4.tags:
                    for day_key in ("\xa9day", "©day", "date"):
                        if day_key in mp4.tags and mp4.tags[day_key]:
                            val = str(mp4.tags[day_key][0])
                            parsed = _parse_iso_datetime(val)
                            if parsed:
                                timestamp = parsed
                                break
                if mp4.tags:
                    meta_details["mp4_tags"] = {k: str(v) for k, v in mp4.tags.items() if not k.startswith("covr")}
            except Exception:
                pass

        # 3. OpenCV frame probe for exact resolution, fps, frame count
        try:
            cap = cv2.VideoCapture(str(media_path))
            if cap.isOpened():
                fps = cap.get(cv2.CAP_PROP_FPS) or 0.0
                frame_count = cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0.0
                width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH) or 0)
                height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT) or 0)
                meta_details["video_resolution"] = f"{width}x{height}"
                meta_details["fps"] = round(fps, 2)
                meta_details["frame_count"] = int(frame_count)
                if (duration_sec is None or duration_sec == 0) and fps > 0 and frame_count > 0:
                    duration_sec = round(frame_count / fps, 2)
            cap.release()
        except Exception:
            pass

    # Fallback to file filesystem last modified timestamp if container has no metadata
    if timestamp is None:
        try:
            mtime = media_path.stat().st_mtime
            timestamp = datetime.fromtimestamp(mtime, tz=timezone.utc)
            meta_details["timestamp_source"] = "FILE_MTIME_FALLBACK"
        except Exception:
            pass
    else:
        meta_details["timestamp_source"] = "CONTAINER_METADATA"

    if duration_sec is not None:
        meta_details["duration_sec"] = duration_sec

    return timestamp, duration_sec, meta_details


def extract_frame_thumbnail(media_path: Path, media_type: Literal["IMAGE", "VIDEO"], max_dim: int = 320) -> Optional[str]:
    """
    Extracts a representative frame / thumbnail as a base64 JPEG string.
    - For video: extracts the midpoint frame via OpenCV.
    - For images: resizes using Pillow.
    """
    try:
        if media_type == "VIDEO":
            cap = cv2.VideoCapture(str(media_path))
            if not cap.isOpened():
                return None

            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
            target_frame = max(0, total_frames // 2)
            if target_frame > 0:
                cap.set(cv2.CAP_PROP_POS_FRAMES, target_frame)

            ret, frame = cap.read()
            if not ret or frame is None:
                # Fallback to first frame
                cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
                ret, frame = cap.read()

            cap.release()

            if not ret or frame is None:
                return None

            h, w = frame.shape[:2]
            if w > 0 and h > 0:
                scale = min(max_dim / w, max_dim / h, 1.0)
                new_w = max(1, int(w * scale))
                new_h = max(1, int(h * scale))
                resized = cv2.resize(frame, (new_w, new_h), interpolation=cv2.INTER_AREA)
                success, buffer = cv2.imencode(".jpg", resized, [int(cv2.IMWRITE_JPEG_QUALITY), 80])
                if success:
                    return base64.b64encode(buffer).decode("utf-8")

        elif media_type == "IMAGE":
            with PIL.Image.open(media_path) as img:
                if img.mode not in ("RGB", "L"):
                    img = img.convert("RGB")
                img.thumbnail((max_dim, max_dim))
                buf = io.BytesIO()
                img.save(buf, format="JPEG", quality=80)
                return base64.b64encode(buf.getvalue()).decode("utf-8")

    except Exception:
        pass
    return None


def check_telemetry_overlap(
    capture_time: Optional[datetime],
    duration_sec: Optional[float],
    telemetry: List[TelemetryPoint],
    image_tolerance_sec: float = 60.0,
    video_padding_sec: float = 15.0
) -> Dict[str, Any]:
    """
    Evaluates whether the media capture timestamp overlaps with the flight telemetry window.
    If overlap is found, determines the closest telemetry coordinates.
    """
    if not capture_time or not telemetry:
        return {
            "has_overlap": False,
            "matched_point": None,
            "time_delta_sec": None,
            "telemetry_window_start": None,
            "telemetry_window_end": None
        }

    # Parse telemetry points to (datetime, TelemetryPoint)
    pts_with_dt: List[Tuple[datetime, TelemetryPoint]] = []
    for pt in telemetry:
        dt = _parse_iso_datetime(pt.timestamp_utc)
        if dt:
            pts_with_dt.append((dt, pt))

    if not pts_with_dt:
        return {
            "has_overlap": False,
            "matched_point": None,
            "time_delta_sec": None,
            "telemetry_window_start": None,
            "telemetry_window_end": None
        }

    telemetry_window_start = min(pts_with_dt, key=lambda x: x[0])[0]
    telemetry_window_end = max(pts_with_dt, key=lambda x: x[0])[0]

    # Find closest telemetry point to the capture time
    closest_dt, closest_pt = min(
        pts_with_dt,
        key=lambda x: abs((x[0] - capture_time).total_seconds())
    )
    time_delta = abs((closest_dt - capture_time).total_seconds())

    has_overlap = False

    if duration_sec and duration_sec > 0:
        # Video spanning [capture_time, capture_time + duration_sec]
        video_start = capture_time
        video_end = capture_time + timedelta(seconds=duration_sec)

        # Overlap if flight window intersects video interval (with tolerance)
        padded_v_start = video_start - timedelta(seconds=video_padding_sec)
        padded_v_end = video_end + timedelta(seconds=video_padding_sec)

        if max(padded_v_start, telemetry_window_start) <= min(padded_v_end, telemetry_window_end):
            has_overlap = True
        elif time_delta <= (duration_sec + video_padding_sec):
            has_overlap = True
    else:
        # Static image: check if nearest telemetry point is within tolerance
        if time_delta <= image_tolerance_sec:
            has_overlap = True

    return {
        "has_overlap": has_overlap,
        "matched_point": closest_pt if has_overlap else None,
        "time_delta_sec": round(time_delta, 2) if has_overlap else None,
        "telemetry_window_start": telemetry_window_start.isoformat(),
        "telemetry_window_end": telemetry_window_end.isoformat()
    }


def process_media_file(
    file_path: Path,
    case_id: str,
    item_id: str,
    telemetry: List[TelemetryPoint],
    client_timestamp: Optional[str] = None,
    save_e01_on_overlap: bool = True
) -> Tuple[MediaCapture, Optional[FlightEvent]]:
    """
    Main processing pipeline for an ingested media asset:
    1. Hashing & type detection
    2. Timestamp & metadata extraction
    3. Representative thumbnail generation
    4. Telemetry overlap detection
    5. Automatic FlightEvent creation if telemetry overlaps
    6. Automatic .eo1 / .E01 forensic image generation for overlapping media
    """
    file_path = Path(file_path)
    manifest = compute_hashes(file_path)
    media_type = detect_media_type(file_path)

    timestamp_dt, duration_sec, meta = extract_media_timestamp_and_details(file_path, media_type)

    # If container did not have internal timestamp and client provided one (e.g. browser lastModified)
    if (timestamp_dt is None or meta.get("timestamp_source") == "FILE_MTIME_FALLBACK") and client_timestamp:
        parsed_client_ts = _parse_iso_datetime(client_timestamp)
        if parsed_client_ts:
            timestamp_dt = parsed_client_ts
            meta["timestamp_source"] = "CLIENT_TIMESTAMP"

    thumbnail_b64 = extract_frame_thumbnail(file_path, media_type)

    overlap_info = check_telemetry_overlap(timestamp_dt, duration_sec, telemetry)

    capture_ts_str = timestamp_dt.isoformat() if timestamp_dt else None
    matched_pt: Optional[TelemetryPoint] = overlap_info.get("matched_point")
    has_overlap: bool = overlap_info["has_overlap"]

    flight_event: Optional[FlightEvent] = None
    event_id: Optional[str] = None

    if has_overlap and matched_pt:
        event_id = f"EVT-MEDIA-{uuid.uuid4().hex[:8].upper()}"
        coords_desc = f"lat={matched_pt.latitude:.5f}, lon={matched_pt.longitude:.5f}, alt={matched_pt.altitude_m:.1f}m"
        dur_desc = f" (duration: {duration_sec:.1f}s)" if duration_sec else ""
        delta_desc = f" [sync delta: {overlap_info['time_delta_sec']}s]" if overlap_info['time_delta_sec'] is not None else ""

        flight_event = FlightEvent(
            event_id=event_id,
            timestamp_utc=capture_ts_str or matched_pt.timestamp_utc,
            event_type="MEDIA_CAPTURE",
            severity="INFO",
            description=f"Media capture synchronized: {file_path.name} ({media_type}){dur_desc} at {coords_desc}{delta_desc}",
            latitude=matched_pt.latitude,
            longitude=matched_pt.longitude,
            altitude_m=matched_pt.altitude_m,
            raw_payload={
                "item_id": item_id,
                "file_name": file_path.name,
                "media_type": media_type,
                "duration_sec": duration_sec,
                "time_delta_sec": overlap_info.get("time_delta_sec"),
                "thumbnail_available": bool(thumbnail_b64),
                "matched_telemetry_time": matched_pt.timestamp_utc
            }
        )

    # If image already had GPS in EXIF, store it in metadata
    if meta.get("has_gps") and meta.get("latitude") is not None:
        meta["exif_gps"] = {
            "latitude": meta.get("latitude"),
            "longitude": meta.get("longitude"),
            "altitude_m": meta.get("altitude_m")
        }

    # Generate .eo1 / .E01 forensic image container when there is telemetry overlap
    e01_path_str: Optional[str] = None
    e01_manifest: Optional[Any] = None
    has_e01 = False

    if has_overlap and save_e01_on_overlap:
        try:
            eo1_file = file_path.parent / f"{file_path.stem}.eo1"
            e01_file = file_path.parent / f"{file_path.stem}.E01"

            # 1. Generate Expert Witness Format E01 Container
            E01Writer.create_e01(
                source_file=file_path,
                output_file=eo1_file,
                case_id=case_id,
                evidence_id=item_id,
                description=f"Synchronized {media_type} Evidence: {file_path.name}",
                notes=f"Overlapping flight media synchronized at {matched_pt.timestamp_utc if matched_pt else 'N/A'}"
            )

            # 2. Also copy/save .E01 for dual extension compatibility (zero '0' vs letter 'o')
            if str(e01_file).lower() != str(eo1_file).lower():
                shutil.copyfile(eo1_file, e01_file)
                WriteBlockController.enforce_file_read_only(e01_file)

            # 3. Enforce write-block
            WriteBlockController.enforce_file_read_only(eo1_file)

            # 4. Compute cryptographic hashes
            e01_manifest = compute_hashes(eo1_file)
            e01_path_str = str(eo1_file)
            has_e01 = True

            meta["e01_saved"] = True
            meta["eo1_path"] = str(eo1_file)
            meta["e01_path"] = str(e01_file)
            meta["e01_sha256"] = e01_manifest.sha256
            meta["e01_size_bytes"] = e01_manifest.byte_count
        except Exception as e:
            meta["e01_error"] = str(e)

    media_capture = MediaCapture(
        item_id=item_id,
        case_id=case_id,
        file_name=file_path.name,
        media_type=media_type,
        file_size_bytes=manifest.byte_count,
        hashes=manifest,
        capture_timestamp_utc=capture_ts_str,
        duration_sec=duration_sec,
        has_telemetry_overlap=has_overlap,
        matched_latitude=matched_pt.latitude if matched_pt else (meta.get("latitude")),
        matched_longitude=matched_pt.longitude if matched_pt else (meta.get("longitude")),
        matched_altitude_m=matched_pt.altitude_m if matched_pt else (meta.get("altitude_m")),
        time_delta_sec=overlap_info.get("time_delta_sec"),
        thumbnail_base64=thumbnail_b64,
        event_id=event_id,
        has_e01=has_e01,
        e01_path=e01_path_str,
        e01_hashes=e01_manifest,
        metadata_details=meta
    )

    return media_capture, flight_event

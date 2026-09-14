"""
Drone Forensic Toolkit (DFT) — Evidence Classification Engine
Automatically classifies and sorts uploaded evidence files into:
1. LOGS: Flight controller blackbox, telemetry logs, mobile flight records (.bin, .ulg, .dat, .txt, .log, .pud, .bbl, .srt, .csv, .db, .sqlite, .gutma, .diff, .dump)
2. VIDEO_IMAGES: Drone payload videos, aerial photography, frame sequences, E01 media containers (.mp4, .mov, .m4v, .avi, .mkv, .jpg, .jpeg, .png, .dng, .tiff, .tif, .bmp, .webp, .eo1)
3. GCS: Ground Control Station mission plans, autonomous survey grids, waypoints, telemetry streams (.plan, .waypoints, .wpl, .kml, .kmz, .tlog, .param, .params, .dpml, .wpml, .mission)
"""

import os
import stat
from pathlib import Path
from typing import Optional, Literal, Tuple, Dict, Any, Union

EvidenceCategory = Literal["LOGS", "VIDEO_IMAGES", "GCS"]


class EvidenceClassifier:
    """
    Forensic classifier for categorizing drone evidence files according to
    operational nature: telemetry logs, visual payload media, or GCS mission data.
    """

    GCS_EXTENSIONS = {
        ".plan", ".waypoints", ".wpl", ".kml", ".kmz", ".tlog",
        ".param", ".params", ".dpml", ".wpml", ".mission", ".mxml"
    }

    VIDEO_EXTENSIONS = {
        ".mp4", ".mov", ".m4v", ".avi", ".mkv", ".wmv", ".flv",
        ".webm", ".ts", ".m2ts", ".3gp"
    }

    IMAGE_EXTENSIONS = {
        ".jpg", ".jpeg", ".png", ".dng", ".tiff", ".tif", ".bmp",
        ".webp", ".raw", ".cr2", ".nef", ".arw"
    }

    LOG_EXTENSIONS = {
        ".bin", ".ulg", ".dat", ".log", ".txt", ".pud", ".bbl",
        ".srt", ".csv", ".db", ".sqlite", ".sqlite3", ".gutma",
        ".diff", ".dump"
    }

    @classmethod
    def classify(
        cls,
        filename_or_path: Union[str, Path],
        content_sample: Optional[bytes] = None
    ) -> EvidenceCategory:
        """
        Classifies an evidence file into LOGS, VIDEO_IMAGES, or GCS based on
        file extension, content headers, and forensic signatures.
        """
        path = Path(filename_or_path)
        ext = path.suffix.lower()
        name_lower = path.name.lower()

        # 1. Ground Control Station (GCS) Checks
        if ext in cls.GCS_EXTENSIONS:
            return "GCS"

        # Check for QGC plan or waypoint headers in sample
        if content_sample:
            try:
                sample_str = content_sample[:2048].decode("utf-8", errors="ignore")
                if sample_str.startswith("#QGC WPL") or "#QGC WPL" in sample_str:
                    return "GCS"
                if '"fileType": "Plan"' in sample_str or '"groundStation"' in sample_str:
                    return "GCS"
                if "<kml" in sample_str.lower() or "<wpml" in sample_str.lower():
                    return "GCS"
            except Exception:
                pass

        # Check with GCSAnalyzer if file exists on disk
        if path.is_file():
            try:
                from dft.analysis.gcs import GCSAnalyzer
                gcs_format, _ = GCSAnalyzer.identify_gcs_format(path)
                if gcs_format:
                    return "GCS"
            except Exception:
                pass

        # 2. Video / Images Checks
        if ext in cls.VIDEO_EXTENSIONS or ext in cls.IMAGE_EXTENSIONS:
            return "VIDEO_IMAGES"

        if ext == ".eo1" or ext.startswith(".e0"):
            # Forensic container created for media
            if "media" in name_lower or "photo" in name_lower or "video" in name_lower:
                return "VIDEO_IMAGES"

        if content_sample:
            # JPEG magic bytes: FF D8 FF
            if content_sample.startswith(b"\xff\xd8\xff"):
                return "VIDEO_IMAGES"
            # PNG magic bytes: 89 50 4E 47
            if content_sample.startswith(b"\x89PNG"):
                return "VIDEO_IMAGES"
            # MP4/MOV ftyp box: bytes 4-8 == 'ftyp'
            if len(content_sample) >= 12 and content_sample[4:8] == b"ftyp":
                return "VIDEO_IMAGES"
            # QuickTime 'moov' or 'mdat'
            if len(content_sample) >= 8 and content_sample[4:8] in (b"moov", b"mdat", b"wide"):
                return "VIDEO_IMAGES"

        # Check with MediaDetector if file exists on disk
        if path.is_file():
            try:
                from dft.analysis.media import MediaDetector
                media_type = MediaDetector.detect_media_type(path)
                if media_type in ("VIDEO", "IMAGE"):
                    return "VIDEO_IMAGES"
            except Exception:
                pass

        # 3. Flight & Mobile Logs
        if ext in cls.LOG_EXTENSIONS:
            return "LOGS"

        # Archive files (.zip, .tar, .tar.gz) often hold mobile backups / flight records
        if ext in (".zip", ".tar", ".gz", ".tgz"):
            return "LOGS"

        # Default fallback is primary flight logs
        return "LOGS"

    @classmethod
    def get_category_folder(cls, category: EvidenceCategory) -> str:
        """Returns the filesystem subdirectory name for a given category."""
        mapping = {
            "LOGS": "logs",
            "VIDEO_IMAGES": "video_images",
            "GCS": "gcs"
        }
        return mapping.get(category, "logs")

    @classmethod
    def get_category_display_name(cls, category: EvidenceCategory) -> str:
        """Returns a user-facing descriptive label for the category."""
        mapping = {
            "LOGS": "Flight & Mobile Logs",
            "VIDEO_IMAGES": "Video & Images",
            "GCS": "Ground Control Station (GCS)"
        }
        return mapping.get(category, "Logs")

    @classmethod
    def get_category_badge(cls, category: EvidenceCategory) -> Dict[str, str]:
        """Returns UI display tokens (icon, label, Tailwind CSS classes) for a category."""
        badges = {
            "LOGS": {
                "icon": "📋",
                "label": "Logs",
                "badge_class": "bg-amber-950/80 text-amber-300 border border-amber-800",
                "pill_bg": "bg-amber-500",
                "color": "#f59e0b"
            },
            "VIDEO_IMAGES": {
                "icon": "🎥",
                "label": "Video/Images",
                "badge_class": "bg-purple-950/80 text-purple-300 border border-purple-800",
                "pill_bg": "bg-purple-500",
                "color": "#a855f7"
            },
            "GCS": {
                "icon": "🎮",
                "label": "GCS",
                "badge_class": "bg-sky-950/80 text-sky-300 border border-sky-800",
                "pill_bg": "bg-sky-500",
                "color": "#0ea5e9"
            }
        }
        return badges.get(category, badges["LOGS"])

    @classmethod
    def sort_and_prepare_destination(
        cls,
        base_case_folder: Path,
        filename: str,
        content_sample: Optional[bytes] = None
    ) -> Tuple[Path, EvidenceCategory, str]:
        """
        Determines the sorted subfolder, creates it if necessary,
        clears read-only bits if an existing file is being overwritten,
        and returns (dest_path, category, subfolder_name).
        """
        category = cls.classify(filename, content_sample=content_sample)
        folder_name = cls.get_category_folder(category)
        target_dir = base_case_folder / folder_name
        target_dir.mkdir(parents=True, exist_ok=True)

        dest_path = target_dir / filename
        if dest_path.exists():
            try:
                os.chmod(dest_path, stat.S_IWRITE)
            except Exception:
                pass

        return dest_path, category, folder_name

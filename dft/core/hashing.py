"""
Dual Cryptographic Hashing Engine for Drone Forensic Toolkit.
Provides simultaneous computation and verification of SHA-256, SHA-3-256, and MD5.
Adheres to ISO/IEC 27037:2012 evidence integrity requirements.
"""

import hashlib
from pathlib import Path
from typing import Union, BinaryIO, Dict, Any
from datetime import datetime, timezone
from dft.core.models import HashManifest

CHUNK_SIZE = 65536  # 64 KB streaming blocks


def compute_hashes(source: Union[str, Path, bytes, BinaryIO]) -> HashManifest:
    """
    Computes SHA-256, SHA-3-256, and MD5 in a single streaming pass.
    Accepts a file path, raw bytes, or an open binary stream.
    """
    h_sha256 = hashlib.sha256()
    h_sha3 = hashlib.sha3_256()
    h_md5 = hashlib.md5()
    total_bytes = 0

    if isinstance(source, bytes):
        h_sha256.update(source)
        h_sha3.update(source)
        h_md5.update(source)
        total_bytes = len(source)
    elif isinstance(source, (str, Path)):
        p = Path(source)
        if not p.exists():
            raise FileNotFoundError(f"Evidence file not found: {source}")
        with open(p, "rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                h_sha256.update(chunk)
                h_sha3.update(chunk)
                h_md5.update(chunk)
                total_bytes += len(chunk)
    elif hasattr(source, "read"):
        while chunk := source.read(CHUNK_SIZE):
            h_sha256.update(chunk)
            h_sha3.update(chunk)
            h_md5.update(chunk)
            total_bytes += len(chunk)
    else:
        raise ValueError(f"Unsupported source type: {type(source)}")

    return HashManifest(
        sha256=h_sha256.hexdigest(),
        sha3_256=h_sha3.hexdigest(),
        md5=h_md5.hexdigest(),
        byte_count=total_bytes,
        computed_at=datetime.now(timezone.utc).isoformat()
    )


def verify_integrity(source: Union[str, Path, bytes, BinaryIO], manifest: HashManifest) -> Dict[str, Any]:
    """
    Recalculates hashes and verifies against an existing manifest.
    Raises exception or returns detailed verification match flags.
    """
    current = compute_hashes(source)
    match_sha256 = (current.sha256.lower() == manifest.sha256.lower())
    match_sha3 = (current.sha3_256.lower() == manifest.sha3_256.lower())
    match_md5 = (current.md5.lower() == manifest.md5.lower())
    match_bytes = (current.byte_count == manifest.byte_count)

    is_valid = match_sha256 and match_sha3 and match_md5 and match_bytes

    return {
        "is_valid": is_valid,
        "match_sha256": match_sha256,
        "match_sha3_256": match_sha3,
        "match_md5": match_md5,
        "match_byte_count": match_bytes,
        "computed": current,
        "expected": manifest
    }

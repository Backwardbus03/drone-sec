"""
Statutory Drone Regulations and Standards Grounding for Drone Forensic Toolkit.
Provides domain context for:
- DGCA UAS Rules 2021 & Drone Rules 2021 (Red / Yellow / Green Zones, DigitalSky)
- ISO/IEC 27037:2012 (Digital Evidence Handling, Preservation, Write-Blocking)
- ISO/IEC 27042:2015 (Analysis and Interpretation of Incident Data)
- FAA 14 CFR Part 107 (Airspace authorizations, 400ft ceiling, visual line-of-sight)
"""

from typing import List, Dict, Any, Optional

REGULATION_CORPUS = [
    {
        "id": "dgca_airspace_zones",
        "title": "DGCA Drone Rules 2021 - Airspace Classification",
        "text": (
            "Under DGCA Drone Rules 2021, Indian airspace is bifurcated into three operational zones: "
            "1. RED ZONE: Absolute No-Fly Zone without prior Central Government permission. Includes 5km around international "
            "borders, 3km around civil/military airports/aerodromes, 2km around strategic installations, government secretariats, "
            "and nuclear facilities. Ground ceiling is strictly 0 meters. Unauthorized entry is a punishable offence under the Aircraft Act. "
            "2. YELLOW ZONE: Controlled airspace between 8km to 12km from an operational airport perimeter or above 400 ft (120m) "
            "in green zones. Requires prior Air Traffic Control (ATC) authorization. "
            "3. GREEN ZONE: Airspace up to 400 ft (120m) not designated as red or yellow. Requires no prior flight permission."
        ),
        "authority": "DGCA / Ministry of Civil Aviation (India)"
    },
    {
        "id": "iso_27037_chain_of_custody",
        "title": "ISO/IEC 27037:2012 - Digital Evidence Integrity & Custody",
        "text": (
            "ISO/IEC 27037:2012 dictates four fundamental digital forensics principles: "
            "1. Auditability: All processes applied to digital evidence must be fully auditable and reproducible by independent examiners. "
            "2. Repeatability: Obtaining identical results when using the same forensic tools on identical copies. "
            "3. Reproducibility: Obtaining comparable results using different tools and methods. "
            "4. Justifiability: Forensics experts must be able to justify all actions and methods chosen during acquisition. "
            "Forensic soundness requires write-blocking at capture, dual cryptographic hashing (SHA-256 + SHA3-256), and HMAC tamper-evident chaining."
        ),
        "authority": "ISO / IEC Standards"
    },
    {
        "id": "faa_part_107_rules",
        "title": "FAA 14 CFR Part 107 - Small Unmanned Aircraft Systems",
        "text": (
            "FAA Part 107 regulations for civil commercial drone operations specify: "
            "1. Maximum allowable altitude is 400 feet (122 meters) Above Ground Level (AGL), or within 400 feet of a structure. "
            "2. Maximum ground speed is 100 mph (87 knots / 45 m/s). "
            "3. Operations in controlled airspace (Class B, C, D, or surface Class E) require prior LAANC or FAA authorization. "
            "4. Anti-collision lighting required for twilight and night operations. "
            "5. Drone must yield right-of-way to all other aircraft."
        ),
        "authority": "Federal Aviation Administration (FAA)"
    }
]


def get_regulation_chunks() -> List[Dict[str, Any]]:
    chunks = []
    for reg in REGULATION_CORPUS:
        text = f"[REGULATION_STANDARD] {reg['title']} | Authority: {reg['authority']} | Provisions: {reg['text']}"
        chunks.append({
            "text": text,
            "metadata": {
                "chunk_type": "regulation_standard",
                "standard_id": reg["id"],
                "authority": reg["authority"],
                "title": reg["title"]
            }
        })
    return chunks


_CACHED_REGULATION_EMBEDDINGS: Optional[List[List[float]]] = None


def get_cached_regulation_chunks_and_embeddings(case_id: str):
    """
    Returns regulation chunks (tagged with case_id) and their precomputed embeddings.
    Embeddings are cached in-memory so static regulations are never repeatedly embedded via API.
    """
    global _CACHED_REGULATION_EMBEDDINGS
    from dft.rag.embedder import embed

    raw_chunks = get_regulation_chunks()
    if _CACHED_REGULATION_EMBEDDINGS is None or len(_CACHED_REGULATION_EMBEDDINGS) != len(raw_chunks):
        texts = [c["text"] for c in raw_chunks]
        _CACHED_REGULATION_EMBEDDINGS = embed(texts)

    case_chunks = []
    for c in raw_chunks:
        c_copy = {
            "text": c["text"],
            "metadata": dict(c["metadata"])
        }
        c_copy["metadata"]["case_id"] = case_id
        case_chunks.append(c_copy)

    return case_chunks, list(_CACHED_REGULATION_EMBEDDINGS)


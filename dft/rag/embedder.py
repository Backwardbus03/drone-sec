"""
Local Embeddings Engine for Drone Forensic Toolkit (DFT).
Uses sentence-transformers locally (all-MiniLM-L6-v2) to maintain complete data privacy
and forensic integrity without sending evidentiary payloads to third-party endpoints.
Includes offline fallback in case the transformer weights are not yet cached.
"""

from typing import List
import math
import hashlib
import numpy as np

_ST_MODEL = None
_INIT_ATTEMPTED = False


def _get_st_model():
    global _ST_MODEL, _INIT_ATTEMPTED
    if _INIT_ATTEMPTED:
        return _ST_MODEL
    _INIT_ATTEMPTED = True
    try:
        from sentence_transformers import SentenceTransformer
        # Load local model (cached in standard huggingface cache)
        _ST_MODEL = SentenceTransformer("all-MiniLM-L6-v2")
    except Exception as err:
        _ST_MODEL = None
    return _ST_MODEL


def _fallback_hash_embed(text: str, dim: int = 384) -> List[float]:
    """
    Deterministically projects text onto a normalized 384-dim vector space
    using hashed n-grams. Used when sentence-transformers or network is unavailable
    in air-gapped forensic environments.
    """
    vec = np.zeros(dim, dtype=np.float32)
    tokens = text.lower().replace(",", " ").replace("|", " ").replace(":", " ").split()
    if not tokens:
        return vec.tolist()

    for token in tokens:
        h = int(hashlib.sha256(token.encode("utf-8")).hexdigest()[:8], 16)
        idx = h % dim
        sign = 1.0 if (h >> 16) % 2 == 0 else -1.0
        vec[idx] += sign

    # Add character 3-grams for semantic sensitivity
    for i in range(len(text) - 2):
        trigram = text[i:i + 3].lower()
        h = int(hashlib.md5(trigram.encode("utf-8")).hexdigest()[:8], 16)
        idx = (h >> 4) % dim
        vec[idx] += 0.5

    norm = np.linalg.norm(vec)
    if norm > 1e-6:
        vec = vec / norm
    return vec.tolist()


def embed(texts: List[str]) -> List[List[float]]:
    """
    Computes vector embeddings for a list of texts.
    Returns a list of 384-dimensional float vectors.
    """
    if not texts:
        return []

    model = _get_st_model()
    if model is not None:
        try:
            embeddings = model.encode(texts, batch_size=32, show_progress_bar=False, normalize_embeddings=True)
            return [e.tolist() for e in embeddings]
        except Exception:
            pass

    # Air-gapped fallback
    return [_fallback_hash_embed(t, dim=384) for t in texts]


def get_embedding_dimension() -> int:
    return 384

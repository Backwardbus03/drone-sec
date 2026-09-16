"""
Embeddings Engine for Drone Forensic Toolkit (DFT).
Uses Google Gemini API for text embeddings (text-embedding-004).
Includes offline fallback.
"""

import os
from typing import List
import hashlib
import numpy as np

def _fallback_hash_embed(text: str, dim: int = 768) -> List[float]:
    """
    Deterministically projects text onto a normalized vector space
    using hashed n-grams. Used when API is unavailable.
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
    Computes vector embeddings for a list of texts using Google Gemini API.
    Returns a list of 768-dimensional float vectors.
    """
    if not texts:
        return []

    api_key = os.getenv("GOOGLE_API_KEY")
    if api_key:
        try:
            from google import genai
            client = genai.Client(api_key=api_key)
            response = client.models.embed_content(
                model='text-embedding-004',
                contents=texts,
            )
            return [e.values for e in response.embeddings]
        except Exception as e:
            print(f"Google API embed error: {e}")
            pass

    # Fallback if API key missing or request fails
    return [_fallback_hash_embed(t, dim=768) for t in texts]


def get_embedding_dimension() -> int:
    return 768

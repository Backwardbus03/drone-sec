"""
Embeddings Engine for Drone Forensic Toolkit (DFT).
Uses Google Gemini API for text embeddings (text-embedding-004).
Includes offline fallback.
"""

import os
import time
import logging
import re
from typing import List
from collections import deque
import hashlib
import numpy as np

logger = logging.getLogger("dft.embedder")

_LAST_CALL_TIMESTAMP = 0.0
# Minimum delay between consecutive batches in seconds
MIN_CALL_INTERVAL_SEC = float(os.getenv("EMBEDDER_RATE_LIMIT_DELAY", "1.5"))
# Google Free Tier enforces a hard cap of 100 items per minute for embed_content.
# We set the maximum ceiling to 80 to provide a safe 20% buffer against quota violations.
MAX_ITEMS_PER_MINUTE = int(os.getenv("EMBEDDER_MAX_ITEMS_PER_MINUTE", "80"))
_CALL_HISTORY: deque = deque()


def _throttle(item_count: int):
    """
    Enforces a strict sliding-window rate limit:
    1. Ensures minimum spacing between consecutive API calls.
    2. Guarantees that total items submitted across any rolling 60-second window <= MAX_ITEMS_PER_MINUTE.
    """
    global _LAST_CALL_TIMESTAMP, _CALL_HISTORY
    now = time.time()

    # 1. Minimum pause between consecutive requests
    elapsed = now - _LAST_CALL_TIMESTAMP
    if elapsed < MIN_CALL_INTERVAL_SEC:
        time.sleep(MIN_CALL_INTERVAL_SEC - elapsed)
        now = time.time()

    # 2. Prune records older than 60 seconds
    cutoff = now - 60.0
    while _CALL_HISTORY and _CALL_HISTORY[0][0] < cutoff:
        _CALL_HISTORY.popleft()

    # 3. Check if adding this batch breaches our rolling minute budget
    current_window_items = sum(count for _, count in _CALL_HISTORY)
    while current_window_items + item_count > MAX_ITEMS_PER_MINUTE and _CALL_HISTORY:
        oldest_ts, _ = _CALL_HISTORY[0]
        sleep_needed = (oldest_ts + 60.05) - time.time()
        if sleep_needed > 0:
            logger.info(
                f"Pacing embedding request to protect 100 items/min quota: "
                f"sleeping {sleep_needed:.1f}s ({current_window_items} items in current 60s window)"
            )
            time.sleep(sleep_needed)
        now = time.time()
        cutoff = now - 60.0
        while _CALL_HISTORY and _CALL_HISTORY[0][0] < cutoff:
            _CALL_HISTORY.popleft()
        current_window_items = sum(count for _, count in _CALL_HISTORY)

    _CALL_HISTORY.append((time.time(), item_count))
    _LAST_CALL_TIMESTAMP = time.time()


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
            from google.genai import types
            client = genai.Client(api_key=api_key)
            
            all_embeddings = []
            # Default batch size 20 items per request
            batch_size = max(1, int(os.getenv("EMBEDDER_BATCH_SIZE", "20")))
            
            for i in range(0, len(texts), batch_size):
                batch_texts = texts[i:i+batch_size]
                
                # Retry loop with exponential backoff for rate limits
                backoff = 5.0
                max_retries = 6
                batch_success = False
                
                for attempt in range(max_retries):
                    try:
                        _throttle(len(batch_texts))
                        response = client.models.embed_content(
                            model='gemini-embedding-001',
                            contents=batch_texts,
                            config=types.EmbedContentConfig(output_dimensionality=768),
                        )
                        all_embeddings.extend([e.values for e in response.embeddings])
                        batch_success = True
                        break
                    except Exception as err:
                        err_str = str(err)
                        is_rate_limit = any(k in err_str for k in ["429", "RESOURCE_EXHAUSTED", "Quota", "quota", "rate limit", "exceeded"])
                        if is_rate_limit and attempt < max_retries - 1:
                            # Parse any explicit wait instruction from Google (e.g. "retry after 10s")
                            retry_match = re.search(r'(?:retry|wait)\s+(?:in|after)?\s*([0-9.]+)\s*s', err_str, re.IGNORECASE)
                            wait_duration = float(retry_match.group(1)) + 1.0 if retry_match else backoff
                            
                            logger.warning(
                                f"Rate limit encountered in embedder (batch {i//batch_size + 1}, attempt {attempt + 1}/{max_retries}). "
                                f"Sleeping for {wait_duration:.1f}s..."
                            )
                            time.sleep(wait_duration)
                            backoff = max(backoff * 2.0, wait_duration * 1.5)
                        else:
                            raise err
                            
                if not batch_success:
                    raise RuntimeError("Failed to embed batch after retries.")
                    
            return all_embeddings
        except Exception as e:
            logger.error(f"Google API embed error: {e}")

    # Fallback if API key missing or request fails
    return [_fallback_hash_embed(t, dim=768) for t in texts]


def get_embedding_dimension() -> int:
    return 768

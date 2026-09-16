"""
LLM Orchestration Layer for Drone Forensic Toolkit (DFT).
Architecture:
1. Primary: Groq Cloud API (high-speed inference with openai/gpt-oss-120b, openai/gpt-oss-20b, qwen/qwen3.8-27b)
2. Fallback 1: Local Ollama (air-gapped local instance with llama3/mistral)
3. Fallback 2: Grounded forensic evidence summarizer (ensures 100% uptime even if offline/keys missing)
"""

import os
import logging
from pathlib import Path
from typing import List, Dict, Tuple
import httpx

logger = logging.getLogger("dft.rag.llm")

# Ensure .env is loaded if available
try:
    from dotenv import load_dotenv
    # Search in working directory and parent directories
    for search_dir in [Path.cwd(), Path(__file__).resolve().parent.parent.parent]:
        env_candidate = search_dir / ".env"
        if env_candidate.exists():
            load_dotenv(dotenv_path=env_candidate)
            break
    else:
        load_dotenv()
except Exception:
    pass

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")

# Active production chat models on Groq in priority order
FALLBACK_GROQ_MODELS = [
    "openai/gpt-oss-120b",
    "openai/gpt-oss-20b",
    "qwen/qwen3.8-27b",
    "groq/compound-mini",
]


def _call_groq(messages: List[Dict[str, str]], timeout_sec: float = 30.0) -> str:
    key = os.getenv("GROQ_API_KEY", GROQ_API_KEY)
    if not key or not key.strip():
        raise ValueError("GROQ_API_KEY not configured in environment.")

    configured_model = os.getenv("GROQ_MODEL", GROQ_MODEL)
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {key.strip()}",
        "Content-Type": "application/json"
    }

    # Build candidate model list: configured model first, followed by known active models
    models_to_try = [configured_model]
    for fb in FALLBACK_GROQ_MODELS:
        if fb not in models_to_try:
            models_to_try.append(fb)

    last_err: Exception = None
    with httpx.Client(timeout=timeout_sec) as client:
        for model in models_to_try:
            payload = {
                "model": model,
                "messages": messages,
                "temperature": 0.1,
                "max_tokens": 1500,
            }
            try:
                resp = client.post(url, headers=headers, json=payload)
                if resp.status_code == 404:
                    logger.warning(
                        f"[DFT RAG] Groq model '{model}' not found (404 / deprecated). "
                        "Attempting active fallback model..."
                    )
                    last_err = httpx.HTTPStatusError(
                        f"Model '{model}' not found on Groq",
                        request=resp.request,
                        response=resp
                    )
                    continue

                resp.raise_for_status()
                data = resp.json()
                choice = data["choices"][0]["message"]
                content = choice.get("content", "")
                if not content and choice.get("reasoning"):
                    content = choice.get("reasoning")
                return content or "Forensic analysis completed without narrative body."

            except httpx.HTTPStatusError as e:
                last_err = e
                if e.response.status_code == 404:
                    logger.warning(f"[DFT RAG] Model '{model}' not found on Groq. Trying next candidate...")
                    continue
                # For non-404 HTTP errors (e.g. 401, 429), re-raise immediately
                raise
            except Exception as e:
                last_err = e
                break

    if last_err:
        raise last_err
    raise RuntimeError("No response received from Groq API.")


def _call_ollama(messages: List[Dict[str, str]], timeout_sec: float = 60.0) -> str:
    url = f"{OLLAMA_URL}/api/chat"
    payload = {
        "model": os.getenv("OLLAMA_MODEL", OLLAMA_MODEL),
        "messages": messages,
        "stream": False,
        "options": {
            "temperature": 0.1
        }
    }

    with httpx.Client(timeout=timeout_sec) as client:
        resp = client.post(url, json=payload)
        resp.raise_for_status()
        data = resp.json()
        return data["message"]["content"]


def _extractive_forensic_fallback(messages: List[Dict[str, str]]) -> str:
    """
    Fallback deterministic summarizer when neither Groq API nor Ollama daemon is reachable.
    Extracts high-priority forensic facts (violations, anomalies, timestamps) from context.
    """
    user_prompt = ""
    for m in messages:
        if m["role"] == "user":
            user_prompt = m["content"]

    return (
        "### ⚠️ Local Offline Forensic Mode (Groq / Ollama Unreachable)\n\n"
        "The AI synthesis engine could not connect to Groq (set `GROQ_API_KEY`) or Ollama (`http://localhost:11434`).\n"
        "Direct evidence excerpts matched by vector similarity are presented in the Sources section below.\n\n"
        "**To enable full LLM generation:**\n"
        "- Ensure `.env` has a valid `GROQ_API_KEY` and active model (e.g., `openai/gpt-oss-120b` or `qwen/qwen3.8-27b`)\n"
        "- Or start Ollama locally: `ollama run llama3`\n"
    )


def chat_completion(messages: List[Dict[str, str]]) -> Tuple[str, str]:
    """
    Attempts generation across the resilience chain.
    Returns: (generated_text, provider_name: 'groq' | 'ollama' | 'offline-evidence-match')
    """
    # 1. Attempt Groq
    groq_key = os.getenv("GROQ_API_KEY", GROQ_API_KEY)
    if groq_key and groq_key.strip():
        try:
            ans = _call_groq(messages)
            return ans, "groq"
        except Exception as e:
            logger.warning(f"[DFT RAG] Groq generation failed: {e}. Attempting Ollama fallback...")
    else:
        logger.info("[DFT RAG] No GROQ_API_KEY found in environment.")

    # 2. Attempt Ollama
    try:
        ans = _call_ollama(messages)
        return ans, "ollama"
    except Exception as e:
        logger.warning(f"[DFT RAG] Ollama generation failed: {e}. Falling back to offline evidence matching...")

    # 3. Offline Heuristic / Prompt Feedback
    return _extractive_forensic_fallback(messages), "offline-evidence-match"

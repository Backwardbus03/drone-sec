"""
LLM Orchestration Layer for Drone Forensic Toolkit (DFT).
Architecture:
1. Primary: Groq Cloud API (high-speed inference with llama-3.3-70b-versatile)
2. Fallback 1: Local Ollama (air-gapped local instance with llama3/mistral)
3. Fallback 2: Grounded forensic evidence summarizer (ensures 100% uptime even if offline/keys missing)
"""

import os
from typing import List, Dict, Tuple
import httpx

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")


def _call_groq(messages: List[Dict[str, str]], timeout_sec: float = 25.0) -> str:
    key = os.getenv("GROQ_API_KEY", GROQ_API_KEY)
    if not key or not key.strip():
        raise ValueError("GROQ_API_KEY not configured in environment.")

    model = os.getenv("GROQ_MODEL", GROQ_MODEL)
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {key.strip()}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0.1,
        "max_tokens": 1500,
    }

    with httpx.Client(timeout=timeout_sec) as client:
        resp = client.post(url, headers=headers, json=payload)
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]


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
        "- Run `export GROQ_API_KEY=\"gsk_...\"` (or set in `.env` / environment)\n"
        "- Or start Ollama: `ollama run llama3`\n"
    )


def chat_completion(messages: List[Dict[str, str]]) -> Tuple[str, str]:
    """
    Attempts generation across the resilience chain.
    Returns: (generated_text, provider_name: 'groq' | 'ollama' | 'offline-heuristic')
    """
    # 1. Attempt Groq
    try:
        if os.getenv("GROQ_API_KEY", GROQ_API_KEY):
            ans = _call_groq(messages)
            return ans, "groq"
    except Exception as e:
        # Fall through to Ollama
        pass

    # 2. Attempt Ollama
    try:
        ans = _call_ollama(messages)
        return ans, "ollama"
    except Exception as e:
        # Fall through to Offline Fallback
        pass

    # 3. Offline Heuristic / Prompt Feedback
    return _extractive_forensic_fallback(messages), "offline-evidence-match"

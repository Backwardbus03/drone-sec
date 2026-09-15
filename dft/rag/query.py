"""
Forensic RAG Query Engine for Drone Forensic Toolkit (DFT).
Coordinates vector similarity search across the case's isolated collection,
formats court-admissible forensic prompt contexts, and routes generation
through Groq with fallback to local Ollama.
"""

from typing import Dict, Any, List, Optional
from dft.rag.embedder import embed
from dft.rag.vector_store import query_case_vector_store, count_case_chunks
from dft.rag.llm import chat_completion

SYSTEM_PROMPT = """You are an expert UAV Digital Forensics Analyst AI assistant operating under ISO/IEC 27037:2012 and ISO/IEC 27042:2015 forensic standards.
Your responsibility is to analyze digital drone evidence (telemetry, flight events, geofence breaches, sensor anomalies, chain of custody logs, and ground control station records) to assist law enforcement and aviation accident investigators.

RULES OF ENGAGEMENT:
1. STRICT GROUNDING: Answer questions based strictly on the provided evidence excerpts. Do not invent, speculate, or hallucinate flight facts not present in the records.
2. CITATION OF EVIDENCE: Whenever referencing flight incidents, always state:
   - The precise UTC timestamp (e.g., 2026-03-12T14:22:10Z).
   - GPS coordinates (latitude, longitude, altitude) if available.
   - Severity level (INFO, WARNING, CRITICAL).
3. STATUTORY COMPLIANCE: If a flight violates DGCA / FAA / ICAO regulations or enters a RED/YELLOW airspace zone, explicitly cite the breach and regulatory implications.
4. CHAIN OF CUSTODY INTEGRITY: If asked about tamper evidence or integrity, confirm whether cryptographic hashes (SHA-256 / SHA3-256) and HMAC signatures verify forensic soundness.
5. UNCERTAINTY: If the evidence does not contain sufficient details to answer a question conclusively, explicitly declare: "The current case records do not contain evidence regarding this aspect."
"""


def answer_case_question(
    case_id: str,
    question: str,
    *,
    top_k: int = 10,
    where: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Executes a forensic RAG retrieval and synthesis workflow for an active case.
    """
    clean_q = question.strip()
    if not clean_q:
        return {
            "answer": "Please provide a valid forensic question.",
            "sources": [],
            "provider": "none",
            "chunks_retrieved": 0
        }

    total_chunks = count_case_chunks(case_id)
    if total_chunks == 0:
        return {
            "answer": (
                f"No forensic evidence has been indexed for Case '{case_id}' yet. "
                "Please click '⚡ Index Evidence' in the AI Analyst tab or parse telemetry logs to index this case."
            ),
            "sources": [],
            "provider": "none",
            "chunks_retrieved": 0
        }

    # 1. Embed query
    q_vec = embed([clean_q])[0]

    # 2. Retrieve top-k chunks
    res = query_case_vector_store(case_id, q_vec, top_k=top_k, where=where)
    raw_docs = res.get("documents", [[]])[0]
    raw_metas = res.get("metadatas", [[]])[0]
    raw_distances = res.get("distances", [[]])[0] if "distances" in res else [0.0] * len(raw_docs)

    if not raw_docs:
        return {
            "answer": "No relevant evidence chunks matched your query criteria.",
            "sources": [],
            "provider": "none",
            "chunks_retrieved": 0
        }

    # Format context blocks
    context_lines = []
    sources = []
    for idx, (doc, meta, dist) in enumerate(zip(raw_docs, raw_metas, raw_distances), 1):
        c_type = meta.get("chunk_type", "general")
        context_lines.append(f"[{idx}] {doc}")
        sources.append({
            "index": idx,
            "text": doc,
            "metadata": meta,
            "relevance_score": round(1.0 - float(dist), 4) if dist is not None else 1.0
        })

    context_payload = "\n\n".join(context_lines)

    # 3. Construct message array
    user_prompt = (
        f"### FORENSIC EVIDENCE EXCERPTS (Case ID: {case_id}):\n"
        f"{context_payload}\n\n"
        f"### INVESTIGATOR QUESTION:\n"
        f"{clean_q}\n\n"
        f"### REQUIRED FORENSIC ANALYSIS:"
    )

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt}
    ]

    # 4. Generate response via resilience router
    answer_text, provider = chat_completion(messages)

    return {
        "answer": answer_text,
        "sources": sources,
        "provider": provider,
        "chunks_retrieved": len(sources),
        "total_case_chunks": total_chunks
    }

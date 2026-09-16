"""
Forensic Vector Store for Drone Forensic Toolkit (DFT).
Manages isolated, per-case vector index collections in ChromaDB.
Persists all vector indices in forensic_cases_vault/vector_db/.
Provides seamless fallback storage if ChromaDB is unavailable.
"""

from pathlib import Path
from typing import List, Dict, Any, Optional
import json
import os
import sqlite3
import numpy as np

VECTOR_DB_DIR = Path(os.getenv("DFT_DATA_DIR", "forensic_cases_vault")) / "vector_db"
VECTOR_DB_DIR.mkdir(parents=True, exist_ok=True)

_CHROMA_CLIENT = None
_CHROMA_AVAILABLE = None


def _get_chroma_client():
    global _CHROMA_CLIENT, _CHROMA_AVAILABLE
    if _CHROMA_AVAILABLE is False:
        return None
    if _CHROMA_CLIENT is not None:
        return _CHROMA_CLIENT

    try:
        import chromadb
        from chromadb.config import Settings
        _CHROMA_CLIENT = chromadb.PersistentClient(
            path=str(VECTOR_DB_DIR.resolve()),
            settings=Settings(anonymized_telemetry=False, is_persistent=True)
        )
        _CHROMA_AVAILABLE = True
        return _CHROMA_CLIENT
    except Exception as e:
        _CHROMA_AVAILABLE = False
        _CHROMA_CLIENT = None
        return None


# --- SQLITE FALLBACK VECTOR ENGINE ---

class SqliteVectorCollection:
    def __init__(self, case_id: str):
        self.case_id = case_id
        self.db_path = VECTOR_DB_DIR / f"sqlite_{case_id}.db"
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS chunks (
                    id TEXT PRIMARY KEY,
                    document TEXT,
                    metadata_json TEXT,
                    embedding_blob BLOB
                )
            """)
            conn.commit()

    def upsert(self, ids: List[str], documents: List[str], embeddings: List[List[float]], metadatas: List[Dict[str, Any]]):
        with sqlite3.connect(self.db_path) as conn:
            for chunk_id, doc, emb, meta in zip(ids, documents, embeddings, metadatas):
                emb_arr = np.array(emb, dtype=np.float32).tobytes()
                meta_json = json.dumps(meta)
                conn.execute("""
                    INSERT OR REPLACE INTO chunks (id, document, metadata_json, embedding_blob)
                    VALUES (?, ?, ?, ?)
                """, (chunk_id, doc, meta_json, emb_arr))
            conn.commit()

    def query(self, query_embeddings: List[List[float]], n_results: int = 8, where: Optional[Dict[str, Any]] = None):
        q_vec = np.array(query_embeddings[0], dtype=np.float32)
        q_norm = np.linalg.norm(q_vec)
        if q_norm > 1e-6:
            q_vec = q_vec / q_norm

        scores = []
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT id, document, metadata_json, embedding_blob FROM chunks")
            for chunk_id, doc, meta_json, emb_blob in cursor.fetchall():
                meta = json.loads(meta_json)
                # Apply where filter if specified
                if where:
                    match = True
                    for k, v in where.items():
                        if meta.get(k) != v:
                            match = False
                            break
                    if not match:
                        continue

                doc_vec = np.frombuffer(emb_blob, dtype=np.float32)
                doc_norm = np.linalg.norm(doc_vec)
                if doc_norm > 1e-6:
                    doc_vec = doc_vec / doc_norm
                score = float(np.dot(q_vec, doc_vec))
                scores.append((score, chunk_id, doc, meta))

        scores.sort(key=lambda x: x[0], reverse=True)
        top = scores[:n_results]

        return {
            "ids": [[item[1] for item in top]],
            "documents": [[item[2] for item in top]],
            "metadatas": [[item[3] for item in top]],
            "distances": [[1.0 - item[0] for item in top]],
        }

    def count(self) -> int:
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute("SELECT COUNT(*) FROM chunks")
            return cur.fetchone()[0]

    def delete(self):
        if self.db_path.exists():
            try:
                self.db_path.unlink()
            except Exception:
                pass


def sanitize_collection_name(case_id: str) -> str:
    """Chroma collection names must be 3-63 chars, alphanumeric or underscores."""
    clean = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in case_id)
    name = f"case_{clean}"
    if len(name) < 3:
        name = "case_001"
    return name[:63]


def get_case_collection(case_id: str):
    client = _get_chroma_client()
    if client is not None:
        col_name = sanitize_collection_name(case_id)
        return client.get_or_create_collection(
            name=col_name,
            metadata={"hnsw:space": "cosine", "case_id": case_id}
        )
    return SqliteVectorCollection(case_id)


def upsert_chunks(case_id: str, chunks: List[Dict[str, Any]], embeddings: List[List[float]]):
    """
    Upserts structured chunks with embeddings into the case's isolated vector collection.
    """
    if not chunks:
        return

    ids = [f"{case_id}_{i}_{chunks[i]['metadata'].get('chunk_type', 'c')}" for i in range(len(chunks))]
    documents = [c["text"] for c in chunks]
    metadatas = [c["metadata"] for c in chunks]

    # Convert complex metadata types to primitives supported by ChromaDB
    sanitized_metadatas = []
    for m in metadatas:
        clean_m = {}
        for k, v in m.items():
            if isinstance(v, (str, int, float, bool)):
                clean_m[k] = v
            else:
                clean_m[k] = str(v)
        sanitized_metadatas.append(clean_m)

    col = get_case_collection(case_id)
    col.upsert(
        ids=ids,
        documents=documents,
        embeddings=embeddings,
        metadatas=sanitized_metadatas
    )


def query_case_vector_store(case_id: str, query_embedding: List[float], top_k: int = 8, where: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Queries the vector store for the top-k most semantically similar chunks in the case collection.
    """
    col = get_case_collection(case_id)
    kwargs = {
        "query_embeddings": [query_embedding],
        "n_results": top_k
    }
    if where:
        kwargs["where"] = where

    return col.query(**kwargs)


def count_case_chunks(case_id: str) -> int:
    col = get_case_collection(case_id)
    return col.count()


def delete_case_collection(case_id: str):
    """Deletes the vector collection when a case is deleted."""
    client = _get_chroma_client()
    if client is not None:
        col_name = sanitize_collection_name(case_id)
        try:
            client.delete_collection(name=col_name)
        except Exception:
            pass
    # Also clean SQLite fallback if present
    SqliteVectorCollection(case_id).delete()

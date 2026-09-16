"""
Forensic Vector Store for Drone Forensic Toolkit (DFT).
Manages isolated, per-case vector index collections.
Migrated to Pinecone Serverless for true free persistence.
"""

import os
from typing import List, Dict, Any, Optional

_pc = None
_index = None

def _get_pinecone_index():
    global _pc, _index
    if _index is not None:
        return _index

    api_key = os.getenv("PINECONE_API_KEY")
    if not api_key:
        print("Warning: PINECONE_API_KEY not set.")
        return None

    index_name = os.getenv("PINECONE_INDEX", "dft-index")
    
    try:
        from pinecone import Pinecone, ServerlessSpec
        _pc = Pinecone(api_key=api_key)
        
        # Check if index exists, create if not
        existing_indexes = [index_info["name"] for index_info in _pc.list_indexes()]
        if index_name not in existing_indexes:
            _pc.create_index(
                name=index_name,
                dimension=768, # Google GenAI embeddings dimension
                metric="cosine",
                spec=ServerlessSpec(cloud="aws", region="us-east-1")
            )
            
        _index = _pc.Index(index_name)
        return _index
    except Exception as e:
        print(f"Error connecting to Pinecone: {e}")
        return None


def upsert_chunks(case_id: str, chunks: List[Dict[str, Any]], embeddings: List[List[float]]):
    """
    Upserts structured chunks with embeddings into the case's isolated Pinecone namespace.
    """
    index = _get_pinecone_index()
    if not index or not chunks:
        return

    vectors = []
    for i, (chunk, emb) in enumerate(zip(chunks, embeddings)):
        chunk_type = chunk["metadata"].get("chunk_type", "c")
        vec_id = f"{case_id}_{i}_{chunk_type}"
        
        # Pinecone metadata values must be strings, numbers, booleans, or lists of strings
        clean_m = {}
        for k, v in chunk["metadata"].items():
            if isinstance(v, (str, int, float, bool)):
                clean_m[k] = v
            else:
                clean_m[k] = str(v)
        
        # We need to store the document text in metadata to retrieve it later
        clean_m["document_text"] = chunk["text"]
        
        vectors.append({
            "id": vec_id,
            "values": emb,
            "metadata": clean_m
        })
        
    try:
        # Upsert in batches of 100
        batch_size = 100
        for i in range(0, len(vectors), batch_size):
            index.upsert(vectors=vectors[i:i+batch_size], namespace=case_id)
    except Exception as e:
        print(f"Failed to upsert to Pinecone: {e}")


def query_case_vector_store(case_id: str, query_embedding: List[float], top_k: int = 8, where: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Queries the vector store for the top-k most semantically similar chunks in the case namespace.
    """
    index = _get_pinecone_index()
    if not index:
        return {"ids": [[]], "documents": [[]], "metadatas": [[]], "distances": [[]]}

    # Convert 'where' dict to Pinecone filter format if provided
    filter_dict = where if where else None

    try:
        res = index.query(
            namespace=case_id,
            vector=query_embedding,
            top_k=top_k,
            include_metadata=True,
            filter=filter_dict
        )
        
        ids = []
        docs = []
        metas = []
        dists = []
        
        for match in res.matches:
            ids.append(match.id)
            dists.append(1.0 - match.score) # Pinecone score is cosine similarity, we return distance
            meta = match.metadata or {}
            docs.append(meta.pop("document_text", ""))
            metas.append(meta)
            
        return {
            "ids": [ids],
            "documents": [docs],
            "metadatas": [metas],
            "distances": [dists]
        }
    except Exception as e:
        print(f"Pinecone query failed: {e}")
        return {"ids": [[]], "documents": [[]], "metadatas": [[]], "distances": [[]]}


def count_case_chunks(case_id: str) -> int:
    index = _get_pinecone_index()
    if not index:
        return 0
    try:
        stats = index.describe_index_stats()
        namespaces = stats.get("namespaces", {})
        if case_id in namespaces:
            return namespaces[case_id].get("vector_count", 0)
    except Exception:
        pass
    return 0


def delete_case_collection(case_id: str):
    """Deletes the vector namespace when a case is deleted."""
    index = _get_pinecone_index()
    if index:
        try:
            index.delete(delete_all=True, namespace=case_id)
        except Exception:
            pass

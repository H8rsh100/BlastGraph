"""Documentation ingestion and vector database storage using Chroma DB."""
import os
from typing import Optional
import chromadb
from langchain_text_splitters import RecursiveCharacterTextSplitter


def ingest_cis_docs(docs_dir: str = "docs_ingest/cis_docs", chroma_dir: str = "./chroma_db") -> int:
    """Read documentation files from docs_dir, chunk text, embed, and persist to Chroma DB.

    Args:
        docs_dir: Path to directory containing CIS benchmark docs or text files.
        chroma_dir: Directory path for Chroma DB storage.

    Returns:
        Number of chunked document snippets stored.
    """
    if not os.path.exists(docs_dir):
        return 0

    documents = []
    metadata_list = []

    for root, _, files in os.walk(docs_dir):
        for file in files:
            if file.endswith((".txt", ".md")):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        text = f.read()
                        if text.strip():
                            documents.append((file_path, text))
                except Exception:
                    continue

    if not documents:
        return 0

    splitter = RecursiveCharacterTextSplitter(chunk_size=300, chunk_overlap=50)
    chunks = []
    chunk_ids = []
    metadatas = []

    chunk_count = 0
    for file_path, text in documents:
        split_texts = splitter.split_text(text)
        for idx, chunk in enumerate(split_texts):
            chunk_count += 1
            chunks.append(chunk)
            chunk_ids.append(f"doc_{chunk_count}")
            metadatas.append({"source": os.path.basename(file_path), "chunk_index": idx})

    if not chunks:
        return 0

    client = chromadb.PersistentClient(path=chroma_dir)
    collection = client.get_or_create_collection(name="cis_benchmarks")
    
    # Upsert documents into collection
    collection.upsert(
        documents=chunks,
        ids=chunk_ids,
        metadatas=metadatas
    )

    return len(chunks)


def retrieve_cis_guidance(query: str, chroma_dir: str = "./chroma_db", top_k: int = 3) -> list[str]:
    """Retrieve top_k relevant CIS guidance snippets for a query from Chroma DB.

    Args:
        query: Query string describing a security issue or resource type.
        chroma_dir: Directory path for Chroma DB storage.
        top_k: Number of results to return.

    Returns:
        List of matching document snippets.
    """
    if not os.path.exists(chroma_dir):
        return []

    try:
        client = chromadb.PersistentClient(path=chroma_dir)
        collection = client.get_or_create_collection(name="cis_benchmarks")
        results = collection.query(query_texts=[query], n_results=top_k)
        
        docs = results.get("documents", [[]])
        if docs and len(docs) > 0:
            return docs[0]
    except Exception:
        pass

    return []

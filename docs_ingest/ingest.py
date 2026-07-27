"""Ingest CIS Benchmark documentation into Chroma DB."""


def ingest_cis_docs(docs_dir: str, chroma_dir: str = "./chroma_db") -> None:
    """Ingest PDF and text documentation into Chroma DB."""
    pass


def retrieve_cis_guidance(query: str, chroma_dir: str = "./chroma_db", top_k: int = 3) -> list[str]:
    """Retrieve security guidance relevant to a query."""
    return []

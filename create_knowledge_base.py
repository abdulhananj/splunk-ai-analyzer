"""Build the local FAISS index from the project security knowledge file."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from langchain_community.document_loaders import TextLoader
from langchain_community.vectorstores import FAISS
from langchain_google_genai import GoogleGenerativeAIEmbeddings
from langchain_text_splitters import CharacterTextSplitter


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def create_knowledge_base() -> None:
    """Embed the supplied text file and save a local FAISS database."""
    if not os.getenv("GOOGLE_API_KEY"):
        raise ValueError("GOOGLE_API_KEY is missing. Add it to your .env file.")

    source = BASE_DIR / "data" / "security_knowledge.txt"
    index_path = BASE_DIR / os.getenv("FAISS_INDEX_PATH", "faiss_index")
    documents = TextLoader(str(source), encoding="utf-8").load()
    chunks = CharacterTextSplitter(chunk_size=1000, chunk_overlap=100).split_documents(
        documents
    )
    embeddings = GoogleGenerativeAIEmbeddings(model="models/text-embedding-004")
    FAISS.from_documents(chunks, embeddings).save_local(str(index_path))
    print(f"Knowledge base created at {index_path}")


if __name__ == "__main__":
    create_knowledge_base()

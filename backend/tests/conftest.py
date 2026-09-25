"""Shared fixtures. Every test runs fully offline:

- API keys are blanked BEFORE any `app.*` import. `load_dotenv()` never
  overrides a variable that's already set, so a developer's real
  backend/.env can't leak in and turn a test run into real Groq/Gemini
  calls (or spend quota).
- The embedding model is replaced with a tiny deterministic fake, so tests
  don't download or load sentence-transformers.
- The database is an in-memory SQLite shared across one test's session and
  the API's request handlers - never backend/sentra.db.
"""
import hashlib
import os
import sys

for _key in ("GROQ_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY",
             "LANGFUSE_SECRET_KEY", "LANGFUSE_PUBLIC_KEY", "LANGFUSE_BASE_URL"):
    os.environ[_key] = ""

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app import db as db_module, llm_client, resolve  # noqa: E402
from app.rules_loader import load_rule_files  # noqa: E402
from app.seed_loader import load_seed_kb  # noqa: E402

SAMPLES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "samples"))


def sample_path(*parts: str) -> str:
    return os.path.join(SAMPLES_DIR, *parts)


def read_sample(*parts: str) -> str:
    with open(sample_path(*parts), encoding="utf-8") as f:
        return f.read()


def _fake_embed(text: str) -> list:
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return [b / 255.0 for b in digest[:16]]


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    """No test ever loads the embedding model or reaches an LLM unless it
    explicitly replaces `llm_client.classify` itself."""
    monkeypatch.setattr(resolve, "embed", _fake_embed)
    monkeypatch.setattr(llm_client, "classify", lambda *a, **k: None)


@pytest.fixture
def engine():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    from app import models  # noqa: F401  (registers tables on Base)
    db_module.Base.metadata.create_all(bind=eng)
    return eng


@pytest.fixture
def db(engine):
    session = sessionmaker(autocommit=False, autoflush=False, bind=engine)()
    load_rule_files(session)
    load_seed_kb(session)
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client(engine, db):
    """FastAPI TestClient bound to the in-memory DB. Deliberately NOT used as
    a context manager, so the app's startup hook (which loads the real
    embedding model and opens the real sentra.db) never runs."""
    from fastapi.testclient import TestClient
    from app.main import app
    from app.db import get_db

    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def _get_test_db():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = _get_test_db
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()

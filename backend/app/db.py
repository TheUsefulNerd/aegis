"""SQLite for the Sept 16 demo build. PostgreSQL is the stated production
choice (see architecture-document.md §2) - swapping later is a connection
string + dialect change, not a rearchitecture, since everything above this
file talks to SQLAlchemy sessions, not to SQLite directly."""
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = "sqlite:///./sentra.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _add_missing_columns():
    """`create_all` creates missing TABLES but never alters an existing one,
    so a `sentra.db` created before a new model column was added would crash
    on the first query touching that column. Anyone who already cloned and
    ran this has such a DB. Every column added since the first build is
    nullable, so a plain `ALTER TABLE ... ADD COLUMN` is always safe here -
    this is deliberately not a general migration tool (no renames, no type
    changes, no drops); Alembic is the answer once Postgres lands."""
    insp = inspect(engine)
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if not insp.has_table(table.name):
                continue
            existing = {c["name"] for c in insp.get_columns(table.name)}
            for col in table.columns:
                if col.name in existing or not col.nullable:
                    continue
                col_type = col.type.compile(dialect=engine.dialect)
                conn.execute(text(f'ALTER TABLE "{table.name}" ADD COLUMN "{col.name}" {col_type}'))


def init_db():
    from . import models  # noqa: F401  (ensures models are registered on Base)
    Base.metadata.create_all(bind=engine)
    _add_missing_columns()

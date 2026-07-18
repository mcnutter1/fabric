"""SQLAlchemy engine, session, and declarative base."""
from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker, Session

from .config import settings

_connect_args = {}
if settings.database_url.startswith("sqlite"):
    _connect_args = {"check_same_thread": False}

engine = create_engine(
    settings.database_url,
    connect_args=_connect_args,
    pool_pre_ping=True,
    future=True,
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all tables. Imports models to register them on the metadata."""
    from . import models  # noqa: F401  (side-effect: register models)

    Base.metadata.create_all(bind=engine)
    _auto_add_columns()


# Columns added to existing tables after their first creation. SQLAlchemy's
# create_all() never ALTERs an existing table, so we patch them in by hand.
# Keep entries idempotent: {table: {column: "<sql type + default>"}}.
_ADDED_COLUMNS = {
    "flow_records": {
        "meta": "JSON",
        "duration_ms": "INTEGER DEFAULT 0",
    },
    "dns_logs": {
        "meta": "JSON",
    },
}


def _auto_add_columns() -> None:
    from sqlalchemy import inspect, text

    insp = inspect(engine)
    existing_tables = set(insp.get_table_names())
    with engine.begin() as conn:
        for table, columns in _ADDED_COLUMNS.items():
            if table not in existing_tables:
                continue
            have = {c["name"] for c in insp.get_columns(table)}
            for col, ddl in columns.items():
                if col not in have:
                    conn.execute(text(f'ALTER TABLE {table} ADD COLUMN {col} {ddl}'))

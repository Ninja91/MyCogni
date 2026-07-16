"""Synchronous SQLite persistence primitives owned by the adapter layer.

This package establishes connection policy, SQLAlchemy metadata, session
creation, and transaction lifecycle. It contains no profile, case, evidence,
credential, or other PII-bearing schema.
"""

from mycogni.adapters.persistence.database import (
    Base,
    SQLiteSettings,
    create_sqlite_engine,
)
from mycogni.adapters.persistence.unit_of_work import (
    SqlAlchemyUnitOfWork,
    create_session_factory,
)

__all__ = (
    "Base",
    "SQLiteSettings",
    "SqlAlchemyUnitOfWork",
    "create_session_factory",
    "create_sqlite_engine",
)

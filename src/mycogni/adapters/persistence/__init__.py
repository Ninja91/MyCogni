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
from mycogni.adapters.persistence.durability import (
    FilesystemMount,
    FilesystemProbe,
    FixedFilesystemProbe,
    ShutdownState,
    SQLiteCheckpoint,
    SQLiteOperatorState,
    SQLiteOwnershipError,
    SQLiteProcessRole,
    SQLiteReadiness,
    SQLiteRecoveryError,
    SQLiteRuntime,
    SQLiteStartupReport,
    SQLiteStorageAssessment,
    SQLiteStorageUnsupported,
    SQLiteWriterLease,
    SystemFilesystemProbe,
    assess_sqlite_storage,
)
from mycogni.adapters.persistence.unit_of_work import (
    SqlAlchemyUnitOfWork,
    create_session_factory,
)

__all__ = (
    "Base",
    "FilesystemMount",
    "FilesystemProbe",
    "FixedFilesystemProbe",
    "ShutdownState",
    "SQLiteCheckpoint",
    "SQLiteOwnershipError",
    "SQLiteOperatorState",
    "SQLiteProcessRole",
    "SQLiteRecoveryError",
    "SQLiteReadiness",
    "SQLiteRuntime",
    "SQLiteSettings",
    "SQLiteStartupReport",
    "SQLiteStorageAssessment",
    "SQLiteStorageUnsupported",
    "SQLiteWriterLease",
    "SqlAlchemyUnitOfWork",
    "SystemFilesystemProbe",
    "assess_sqlite_storage",
    "create_session_factory",
    "create_sqlite_engine",
)

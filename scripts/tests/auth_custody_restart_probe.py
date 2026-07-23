"""Fresh-interpreter AUTH-001B probe; emits no output or secret material."""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

from mycogni.adapters.auth import OsTokenSource, SqliteAuthDecisionStore
from mycogni.adapters.auth.owner_file_custody import OwnerFileAuthCustody
from mycogni.adapters.persistence import FixedFilesystemProbe, SQLiteRuntime, SQLiteSettings
from mycogni.application.auth_custody import AuthCustodyBinding
from mycogni.bootstrap.auth_custody import open_custodied_auth
from mycogni.domain import OpaqueId


class _Clock:
    def now(self) -> datetime:
        return datetime(2030, 1, 1, tzinfo=UTC)


def main(arguments: list[str]) -> int:
    if len(arguments) != 6:
        return 64
    database_path, custody_path, managed_root = map(Path, arguments[:3])
    binding = AuthCustodyBinding(
        OpaqueId.parse(arguments[3]),
        OpaqueId.parse(arguments[4]),
        OpaqueId.parse(arguments[5]),
    )
    runtime = SQLiteRuntime.open(
        SQLiteSettings(url=f"sqlite:///{database_path}"),
        probe=FixedFilesystemProbe("ext4"),
    )
    try:
        composition = open_custodied_auth(
            expected=binding,
            custody=OwnerFileAuthCustody(
                path=custody_path,
                managed_roots=(managed_root,),
            ),
            clock=_Clock(),
            token_source=OsTokenSource(),
            store=SqliteAuthDecisionStore(runtime),
        )
        outcome = composition.service.emergency_revoke(composition.roots.emergency_revoke)
        return 0 if outcome.denial is None else 65
    finally:
        runtime.close_cleanly()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

"""Adversarial AUTH-001B owner-file and restart evidence."""

from __future__ import annotations

import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config

from mycogni.adapters.auth import OsTokenSource, SqliteAuthDecisionStore
from mycogni.adapters.auth.owner_file_custody import (
    OwnerFileAuthCustody,
    OwnerFileAuthCustodyProvisioner,
)
from mycogni.adapters.auth.volatile import VolatileAuthDecisionStore
from mycogni.adapters.persistence import FixedFilesystemProbe, SQLiteRuntime, SQLiteSettings
from mycogni.application.auth import AuthCapabilityDisabled
from mycogni.application.auth_custody import (
    AuthCustodyBinding,
    AuthCustodyError,
    AuthCustodyFailureCode,
    AuthCustodyStatus,
)
from mycogni.bootstrap.auth_custody import (
    mint_auth_custody_bundle,
    open_custodied_auth,
    provision_custodied_auth,
)
from mycogni.domain import OpaqueId
from mycogni.domain.auth import AuthDenial

REPOSITORY_ROOT = Path(__file__).parents[3]
NOW = datetime(2030, 1, 1, tzinfo=UTC)


class FixedClock:
    def now(self) -> datetime:
        return NOW


class CountingTokenSource:
    def __init__(self) -> None:
        self.count = 0

    def generate(self, length: int) -> bytes:
        self.count += 1
        return os.urandom(length)


def _layout(tmp_path: Path) -> tuple[Path, tuple[Path, ...]]:
    custody = tmp_path / "host-secrets"
    custody.mkdir(mode=0o700)
    managed = tmp_path / "managed-data"
    managed.mkdir(mode=0o700)
    return custody / "auth.bundle", (managed,)


def _binding() -> AuthCustodyBinding:
    return AuthCustodyBinding(OpaqueId.new(), OpaqueId.new(), OpaqueId.new())


def _provision(path: Path, roots: tuple[Path, ...], binding: AuthCustodyBinding) -> None:
    bundle = mint_auth_custody_bundle(binding=binding, token_source=OsTokenSource())
    OwnerFileAuthCustodyProvisioner(path=path, managed_roots=roots).provision_empty(bundle)


def _migrate(path: Path) -> None:
    config = Config(REPOSITORY_ROOT / "alembic.ini")
    config.set_main_option("script_location", str(REPOSITORY_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{path}")
    command.upgrade(config, "head")


def _open(path: Path) -> SQLiteRuntime:
    return SQLiteRuntime.open(
        SQLiteSettings(url=f"sqlite:///{path}"), probe=FixedFilesystemProbe("ext4")
    )


def test_round_trip_is_fixed_binary_and_redacted(tmp_path: Path) -> None:
    path, roots = _layout(tmp_path)
    binding = _binding()
    _provision(path, roots, binding)
    provider = OwnerFileAuthCustody(path=path, managed_roots=roots)

    assert provider.status(binding) is AuthCustodyStatus.READY
    bundle = provider.load(binding)
    assert bundle.binding == binding
    assert bundle.generation == 1
    assert "REDACTED" in repr(bundle)
    assert "REDACTED" in repr(provider)
    assert not path.read_bytes().startswith(b"{")


@pytest.mark.parametrize(
    ("offset", "value"),
    ((0, 0), (16, 9), (17, 4), (74, 99)),
)
def test_parser_rejects_magic_version_count_and_tag(
    tmp_path: Path, offset: int, value: int
) -> None:
    path, roots = _layout(tmp_path)
    binding = _binding()
    _provision(path, roots, binding)
    payload = bytearray(path.read_bytes())
    payload[offset] = value
    path.chmod(0o600)
    path.write_bytes(payload)
    provider = OwnerFileAuthCustody(path=path, managed_roots=roots)

    assert provider.status(binding) is AuthCustodyStatus.RECOVERY_REQUIRED
    with pytest.raises(AuthCustodyError) as captured:
        provider.load(binding)
    assert captured.value.code is AuthCustodyFailureCode.RECOVERY_REQUIRED


def test_wrong_binding_latches_without_disclosure(tmp_path: Path) -> None:
    path, roots = _layout(tmp_path)
    binding = _binding()
    _provision(path, roots, binding)
    wrong = _binding()
    provider = OwnerFileAuthCustody(path=path, managed_roots=roots)

    with pytest.raises(AuthCustodyError) as captured:
        provider.load(wrong)
    rendered = f"{captured.value!s} {captured.value!r}"
    assert captured.value.code is AuthCustodyFailureCode.BINDING_MISMATCH
    assert str(path) not in rendered
    assert str(binding.installation_id) not in rendered
    assert provider.status(binding) is AuthCustodyStatus.RECOVERY_REQUIRED


def test_create_new_never_overwrites_or_changes_existing_mode(tmp_path: Path) -> None:
    path, roots = _layout(tmp_path)
    first = _binding()
    _provision(path, roots, first)
    original = path.read_bytes()
    path.chmod(0o400)
    second = mint_auth_custody_bundle(binding=_binding(), token_source=OsTokenSource())

    with pytest.raises(AuthCustodyError) as captured:
        OwnerFileAuthCustodyProvisioner(path=path, managed_roots=roots).provision_empty(second)
    assert captured.value.code is AuthCustodyFailureCode.ALREADY_PROVISIONED
    assert path.read_bytes() == original
    assert path.stat().st_mode & 0o777 == 0o400


@pytest.mark.parametrize("mode", (0o644, 0o660, 0o200))
def test_unsafe_mode_denies_and_latches(tmp_path: Path, mode: int) -> None:
    path, roots = _layout(tmp_path)
    binding = _binding()
    _provision(path, roots, binding)
    path.chmod(mode)
    provider = OwnerFileAuthCustody(path=path, managed_roots=roots)

    assert provider.status(binding) is AuthCustodyStatus.RECOVERY_REQUIRED
    path.chmod(0o600)
    assert provider.status(binding) is AuthCustodyStatus.RECOVERY_REQUIRED


def test_symlink_and_hardlink_sources_are_denied(tmp_path: Path) -> None:
    path, roots = _layout(tmp_path)
    binding = _binding()
    _provision(path, roots, binding)
    target = path.with_name("target")
    path.rename(target)
    path.symlink_to(target)
    assert (
        OwnerFileAuthCustody(path=path, managed_roots=roots).status(binding)
        is AuthCustodyStatus.RECOVERY_REQUIRED
    )
    path.unlink()
    os.link(target, path)
    assert (
        OwnerFileAuthCustody(path=path, managed_roots=roots).status(binding)
        is AuthCustodyStatus.RECOVERY_REQUIRED
    )


def test_dangling_symlink_is_not_reported_unprovisioned(tmp_path: Path) -> None:
    path, roots = _layout(tmp_path)
    path.symlink_to(path.with_name("absent-target"))
    assert (
        OwnerFileAuthCustody(path=path, managed_roots=roots).status(_binding())
        is AuthCustodyStatus.RECOVERY_REQUIRED
    )


def test_pinned_replacement_latches_permanently(tmp_path: Path) -> None:
    path, roots = _layout(tmp_path)
    binding = _binding()
    _provision(path, roots, binding)
    provider = OwnerFileAuthCustody(path=path, managed_roots=roots)
    assert provider.load(binding).binding == binding
    old = path.with_suffix(".old")
    path.rename(old)
    replacement = path.with_suffix(".replacement")
    replacement.write_bytes(old.read_bytes())
    replacement.chmod(0o600)
    replacement.rename(path)

    assert provider.status(binding) is AuthCustodyStatus.RECOVERY_REQUIRED
    path.unlink()
    old.rename(path)
    assert provider.status(binding) is AuthCustodyStatus.RECOVERY_REQUIRED


def test_managed_root_overlap_is_rejected_both_directions(tmp_path: Path) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    nested = private / "nested"
    nested.mkdir(mode=0o700)
    with pytest.raises(AuthCustodyError) as first:
        OwnerFileAuthCustody(path=nested / "auth", managed_roots=(private,))
    with pytest.raises(AuthCustodyError) as second:
        OwnerFileAuthCustody(path=private / "auth", managed_roots=(nested,))
    assert first.value.code is second.value.code is AuthCustodyFailureCode.UNSAFE_STORAGE


def test_managed_root_symlink_ancestor_is_rejected(tmp_path: Path) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    real = tmp_path / "real-managed"
    real.mkdir(mode=0o700)
    linked = tmp_path / "linked-managed"
    linked.symlink_to(real, target_is_directory=True)
    with pytest.raises(AuthCustodyError) as captured:
        OwnerFileAuthCustody(path=private / "auth", managed_roots=(linked / "nested",))
    assert captured.value.code is AuthCustodyFailureCode.UNSAFE_STORAGE


def test_runtime_reader_structurally_lacks_provisioning(tmp_path: Path) -> None:
    path, roots = _layout(tmp_path)
    provider = OwnerFileAuthCustody(path=path, managed_roots=roots)
    assert not hasattr(provider, "provision_empty")
    assert not path.exists()


def test_custodied_service_blocks_reprovision_before_material_or_store_mutation(
    tmp_path: Path,
) -> None:
    path, roots = _layout(tmp_path)
    binding = _binding()
    store = VolatileAuthDecisionStore()
    tokens = CountingTokenSource()
    composition = provision_custodied_auth(
        binding=binding,
        provisioner=OwnerFileAuthCustodyProvisioner(path=path, managed_roots=roots),
        clock=FixedClock(),
        token_source=tokens,
        store=store,
    )
    before = store.export_durable_state_v1()
    generated = tokens.count

    with pytest.raises(AuthCapabilityDisabled):
        composition.service.begin_reprovision(composition.roots.reprovision.credential)
    with pytest.raises(AuthCapabilityDisabled):
        composition.service.authorize_reprovision_ceremony(
            composition.roots.reprovision.credential,
            composition.operator_authority,
        )
    with pytest.raises(AuthCapabilityDisabled):
        composition.service.exchange_confirmed_reprovision(
            composition.roots.reprovision.credential,
            None,
        )

    assert tokens.count == generated
    assert store.export_durable_state_v1() == before


def test_true_restart_reopens_custody_and_injects_service_identity(tmp_path: Path) -> None:
    custody_path, managed_roots = _layout(tmp_path)
    database_path = managed_roots[0] / "auth.sqlite"
    _migrate(database_path)
    binding = _binding()
    runtime = _open(database_path)
    try:
        store = SqliteAuthDecisionStore(runtime)
        provisioner = OwnerFileAuthCustodyProvisioner(
            path=custody_path, managed_roots=managed_roots
        )
        composition = provision_custodied_auth(
            binding=binding,
            provisioner=provisioner,
            clock=FixedClock(),
            token_source=OsTokenSource(),
            store=store,
        )
        controlled_bundle = OwnerFileAuthCustody(
            path=custody_path, managed_roots=managed_roots
        ).load(binding)
        raw_authorities = tuple(
            credential.secret.reveal()
            for credential in (
                controlled_bundle.operator_authority.credential,
                controlled_bundle.service_identity,
                *(root.credential for root in controlled_bundle.roots),
            )
        )
        issued = composition.service.begin_bootstrap(composition.roots.initial_bootstrap)
        assert issued.value is not None
        exchanged = composition.service.exchange_bootstrap(issued.value)
        assert exchanged.value is not None
        session = exchanged.value.session
        replay = issued.value
        for candidate in (
            database_path,
            Path(f"{database_path}-wal"),
            Path(f"{database_path}-shm"),
        ):
            if candidate.exists():
                persisted = candidate.read_bytes()
                assert all(secret not in persisted for secret in raw_authorities)
    finally:
        runtime.close_cleanly()
    del controlled_bundle, composition, provisioner, store, runtime

    probe = REPOSITORY_ROOT / "scripts/tests/auth_custody_restart_probe.py"
    completed = subprocess.run(
        [
            sys.executable,
            str(probe),
            str(database_path),
            str(custody_path),
            str(managed_roots[0]),
            str(binding.installation_id),
            str(binding.actor_id),
            str(binding.represented_profile_id),
        ],
        cwd=REPOSITORY_ROOT,
        env={"PYTHONHASHSEED": "0"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    assert completed.returncode == 0

    restarted = _open(database_path)
    try:
        reopened = open_custodied_auth(
            expected=binding,
            custody=OwnerFileAuthCustody(path=custody_path, managed_roots=managed_roots),
            clock=FixedClock(),
            token_source=OsTokenSource(),
            store=SqliteAuthDecisionStore(restarted),
        )
        assert reopened.service.authenticate_session(session).denial is AuthDenial.STALE_EPOCH
        assert reopened.service.exchange_bootstrap(replay).denial is AuthDenial.REPLAYED
    finally:
        restarted.close_cleanly()


def test_presence_mismatch_and_digest_mismatch_fail_closed(tmp_path: Path) -> None:
    custody_path, managed_roots = _layout(tmp_path)
    database_path = managed_roots[0] / "auth.sqlite"
    _migrate(database_path)
    binding = _binding()
    _provision(custody_path, managed_roots, binding)
    runtime = _open(database_path)
    try:
        with pytest.raises(AuthCustodyError) as absent_state:
            open_custodied_auth(
                expected=binding,
                custody=OwnerFileAuthCustody(path=custody_path, managed_roots=managed_roots),
                clock=FixedClock(),
                token_source=OsTokenSource(),
                store=SqliteAuthDecisionStore(runtime),
            )
        assert absent_state.value.code is AuthCustodyFailureCode.RECOVERY_REQUIRED
    finally:
        runtime.close_cleanly()


def test_same_binding_with_different_authorities_is_rejected_before_service(
    tmp_path: Path,
) -> None:
    custody_path, managed_roots = _layout(tmp_path)
    database_path = managed_roots[0] / "auth.sqlite"
    _migrate(database_path)
    binding = _binding()
    runtime = _open(database_path)
    try:
        provision_custodied_auth(
            binding=binding,
            provisioner=OwnerFileAuthCustodyProvisioner(
                path=custody_path, managed_roots=managed_roots
            ),
            clock=FixedClock(),
            token_source=OsTokenSource(),
            store=SqliteAuthDecisionStore(runtime),
        )
        custody_path.unlink()
        _provision(custody_path, managed_roots, binding)
        with pytest.raises(AuthCustodyError) as captured:
            open_custodied_auth(
                expected=binding,
                custody=OwnerFileAuthCustody(path=custody_path, managed_roots=managed_roots),
                clock=FixedClock(),
                token_source=OsTokenSource(),
                store=SqliteAuthDecisionStore(runtime),
            )
        assert captured.value.code is AuthCustodyFailureCode.BINDING_MISMATCH
    finally:
        runtime.close_cleanly()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires POSIX fork")
def test_fork_child_denies_before_inherited_lock_or_io(tmp_path: Path) -> None:
    path, roots = _layout(tmp_path)
    binding = _binding()
    _provision(path, roots, binding)
    provider = OwnerFileAuthCustody(path=path, managed_roots=roots)
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:  # pragma: no cover - asserted by parent through pipe
        os.close(read_fd)
        try:
            provider.load(binding)
        except AuthCustodyError as error:
            os.write(write_fd, error.code.value.encode("ascii"))
        finally:
            os.close(write_fd)
        os._exit(0)
    os.close(write_fd)
    result = os.read(read_fd, 128).decode("ascii")
    os.close(read_fd)
    waited, status = os.waitpid(pid, 0)
    assert waited == pid and os.waitstatus_to_exitcode(status) == 0
    assert result == AuthCustodyFailureCode.FORKED_PROCESS.value

"""Architecture, secret-redaction, and immutable-alias checks for SPIKE-RUNNER."""

from __future__ import annotations

import ast
import traceback
from dataclasses import FrozenInstanceError
from pathlib import Path
from uuid import UUID

import pytest

from services.runner_mailbox import MailboxError, RunnerMailboxService, SystemCredentialSource
from services.runner_mailbox.domain import ActionBinding, EvidenceSeal, EvidenceUpload
from tests.runner_mailbox.conftest import (
    CLAIM_CREDENTIAL,
    EVIDENCE_ID,
    MAILBOX_ID,
)

ROOT = Path(__file__).parents[2]
SERVICE_ROOT = ROOT / "services" / "runner_mailbox"
PROTOCOL_ROOT = ROOT / "packages" / "mycogni-connector-sdk" / "src" / "connector_protocol"
FORBIDDEN_IMPORTS = {
    "http.client",
    "httpx",
    "mycogni",
    "requests",
    "socket",
    "subprocess",
    "urllib.request",
}
FORBIDDEN_CALLS = {"eval", "exec", "open", "print"}


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def test_mailbox_service_never_imports_trusted_core_or_network_process_modules() -> None:
    for path in sorted(SERVICE_ROOT.glob("*.py")):
        for node in ast.walk(_tree(path)):
            if isinstance(node, ast.Import):
                imported = {alias.name for alias in node.names}
                assert not {
                    forbidden
                    for forbidden in FORBIDDEN_IMPORTS
                    if any(
                        name == forbidden or name.startswith(f"{forbidden}.") for name in imported
                    )
                }
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                imported = node.module or ""
                assert not any(
                    imported == forbidden or imported.startswith(f"{forbidden}.")
                    for forbidden in FORBIDDEN_IMPORTS
                )
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in FORBIDDEN_CALLS


def test_connector_protocol_does_not_import_mailbox_or_trusted_core() -> None:
    for path in sorted(PROTOCOL_ROOT.glob("*.py")):
        source = path.read_text(encoding="utf-8")
        assert "services.runner_mailbox" not in source
        assert "mycogni" not in {
            alias.name.partition(".")[0]
            for node in ast.walk(_tree(path))
            if isinstance(node, ast.Import)
            for alias in node.names
        }


def test_claim_secrets_are_absent_from_repr_errors_and_snapshots(
    offered: RunnerMailboxService,
    binding: ActionBinding,
) -> None:
    claim = offered.claim(binding, claim_credential=CLAIM_CREDENTIAL)
    secret_values = (claim.action_key, claim.result_credential, claim.envelope_json)
    claim_repr = repr(claim).encode()
    snapshot_repr = repr(offered.snapshot(UUID(MAILBOX_ID))).encode()
    assert all(value not in claim_repr for value in secret_values)
    assert all(value not in snapshot_repr for value in secret_values)

    private_canary = b"z" * 32
    with pytest.raises(MailboxError) as denied:
        offered.stage_evidence(
            binding,
            result_credential=private_canary,
            evidence=EvidenceUpload(
                object_id=UUID(EVIDENCE_ID),
                kind="sanitized_html",
                ciphertext_digest="sha256:" + "a" * 64,
                ciphertext=b"sealed",
            ),
        )
    assert private_canary not in str(denied.value).encode()
    assert private_canary not in repr(denied.value).encode()


def test_public_evidence_types_reject_mutable_or_weakly_typed_aliases(
    binding: ActionBinding,
) -> None:
    with pytest.raises(ValueError, match="non-empty bytes"):
        EvidenceUpload(
            object_id=UUID(EVIDENCE_ID),
            kind="sanitized_html",
            ciphertext_digest="sha256:" + "a" * 64,
            ciphertext=bytearray(b"mutable"),  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError, match="positive bounded integer"):
        EvidenceSeal(
            object_id=UUID(EVIDENCE_ID),
            kind="sanitized_html",
            ciphertext_digest="sha256:" + "a" * 64,
            byte_count=True,  # type: ignore[arg-type]
        )
    with pytest.raises(FrozenInstanceError):
        binding.fence = 3


def test_missing_mailbox_error_contains_no_identifier(
    service: RunnerMailboxService,
) -> None:
    missing = UUID("7f29ed50-fb6c-4d92-905b-b90a9c9f7ea0")
    with pytest.raises(MailboxError) as denied:
        service.snapshot(missing)
    assert str(missing) not in str(denied.value)


def test_system_result_credentials_are_fresh_256_bit_bytes() -> None:
    source = SystemCredentialSource()
    first = source.issue()
    second = source.issue()
    assert type(first) is bytes and len(first) == 32
    assert type(second) is bytes and len(second) == 32
    assert first != second


def test_protocol_validation_traceback_suppresses_raw_input_and_chained_errors(
    service: RunnerMailboxService,
) -> None:
    private_canary = b"sealed-private-canary-" + b"x" * 32
    invalid = b'{"future_secret":"' + private_canary + b'"}'
    try:
        service.bind_action(
            UUID(MAILBOX_ID),
            invalid,
            selected_artifact_digest="sha256:" + "a" * 64,
            dispatch_epoch=0,
        )
    except MailboxError as exc:
        formatted = "".join(traceback.format_exception(exc)).encode()
        assert exc.__cause__ is None
        assert exc.__context__ is not None
        assert private_canary not in formatted
    else:
        raise AssertionError("invalid action unexpectedly parsed")

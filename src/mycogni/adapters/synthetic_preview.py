"""POSIX state and packaged-fixture adapter for the synthetic preview."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import stat
from contextlib import suppress
from importlib.resources import files
from pathlib import Path
from typing import Any, NoReturn, cast

from mycogni.application.synthetic_preview import (
    DemoReport,
    HealthCheck,
    PreviewReason,
    PreviewReport,
    SyntheticPreviewError,
)

MANIFEST_NAME = "installation.v1.json"
MARKER_NAME = ".initialize.v1"
TEMP_MANIFEST_NAME = ".installation.v1.json.tmp"
MAX_DOCUMENT_BYTES = 128 * 1024
CATALOG_SCHEMA = "mycogni.synthetic-scenarios.v1"
EXPECTED_CATALOG_DIGEST = "243cdf092de4a89941d1ccee72959fe0f2113dd4a7db8d3f2254bab6ca0ef24d"
CORPUS_SCHEMA = "mycogni.synthetic-corpus.v2"
EXPECTED_CORPUS_DIGEST = "0ca849442e82a51bc9d4e445b074420534c403c96abd54f906d9fa5a659b2794"
MANIFEST = {
    "external_capabilities": "absent",
    "fixture_profile": "reserved-domain-simulator-v1",
    "format_version": 1,
    "profile": "developer_preview_synthetic_only",
}


def _error(reason: PreviewReason) -> SyntheticPreviewError:
    return SyntheticPreviewError(reason)


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()


def _validate_absolute(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or "\x00" in value:
        raise _error(PreviewReason.USAGE_ERROR)
    return path


def _directory_fd(path: Path, *, create: bool) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    if path == Path(path.anchor):
        raise _error(PreviewReason.UNSAFE_STORAGE)
    try:
        descriptor = os.open(path.anchor, flags)
        for index, component in enumerate(path.parts[1:]):
            final = index == len(path.parts[1:]) - 1
            if final and create:
                with suppress(FileExistsError):
                    os.mkdir(component, 0o700, dir_fd=descriptor)
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        metadata = os.fstat(descriptor)
    except OSError as error:
        if "descriptor" in locals():
            os.close(descriptor)
        if error.errno in {errno.ENOSPC, getattr(errno, "EDQUOT", errno.ENOSPC)}:
            raise _error(PreviewReason.STORAGE_EXHAUSTED) from None
        raise _error(PreviewReason.UNSAFE_STORAGE) from None
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        os.close(descriptor)
        raise _error(PreviewReason.UNSAFE_STORAGE)
    return descriptor


def _raise_storage(error: OSError) -> NoReturn:
    if error.errno in {errno.ENOSPC, getattr(errno, "EDQUOT", errno.ENOSPC)}:
        raise _error(PreviewReason.STORAGE_EXHAUSTED) from None
    raise _error(PreviewReason.STORAGE_IO_FAILURE) from None


def _managed_file(directory_fd: int, name: str, *, limit: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size > limit
        ):
            raise _error(PreviewReason.STATE_INCOMPATIBLE)
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 8192))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > limit:
            raise _error(PreviewReason.STATE_INCOMPATIBLE)
        return data
    except SyntheticPreviewError:
        raise
    except FileNotFoundError:
        raise _error(PreviewReason.NOT_INITIALIZED) from None
    except OSError:
        raise _error(PreviewReason.STATE_INCOMPATIBLE) from None
    finally:
        if "descriptor" in locals():
            os.close(descriptor)


def _read_exact_manifest(directory_fd: int, name: str) -> dict[str, Any]:
    raw = _managed_file(directory_fd, name, limit=4096)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise _error(PreviewReason.STATE_INCOMPATIBLE) from None
    if value != MANIFEST or raw != _canonical(MANIFEST) + b"\n":
        raise _error(PreviewReason.STATE_INCOMPATIBLE)
    return cast(dict[str, Any], value)


def _read_manifest(directory_fd: int) -> dict[str, Any]:
    return _read_exact_manifest(directory_fd, MANIFEST_NAME)


def _fixture_document(name: str, schema: str, expected_digest: str) -> tuple[dict[str, Any], str]:
    try:
        raw = files("mycogni.synthetic_fixtures").joinpath(name).read_bytes()
        if len(raw) > MAX_DOCUMENT_BYTES:
            raise ValueError
        value = json.loads(raw)
        if not isinstance(value, dict) or value.get("schema") != schema:
            raise ValueError
        supplied = value.get("canonical_hash")
        payload = {key: item for key, item in value.items() if key != "canonical_hash"}
        digest = hashlib.sha256(_canonical(payload)).hexdigest()
        if supplied != digest or digest != expected_digest:
            raise ValueError
        return value, digest
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
        raise _error(PreviewReason.STATE_INCOMPATIBLE) from None


def _fixture_catalog() -> tuple[dict[str, Any], str]:
    value, digest = _fixture_document("scenarios.v1.json", CATALOG_SCHEMA, EXPECTED_CATALOG_DIGEST)
    try:
        scenarios = value.get("scenarios")
        if not isinstance(scenarios, list):
            raise ValueError
        _fixture_document("corpus.v2.json", CORPUS_SCHEMA, EXPECTED_CORPUS_DIGEST)
        return value, digest
    except (ValueError, TypeError):
        raise _error(PreviewReason.STATE_INCOMPATIBLE) from None


def _checks() -> tuple[HealthCheck, ...]:
    return (
        HealthCheck("state_layout", "ready", "pass"),
        HealthCheck("fixtures", "verified", "pass"),
        HealthCheck("authentication", "not_composed", "not_applicable"),
        HealthCheck("key_custody", "not_composed", "not_applicable"),
        HealthCheck("external_actions", "unavailable_by_composition", "not_applicable"),
        HealthCheck("runtime_network_containment", "not_proven", "not_applicable"),
    )


class PosixSyntheticPreview:
    """Own the deliberately non-production manifest and reviewed fixture catalog."""

    def initialize(self, state_dir: str) -> PreviewReport:
        path = _validate_absolute(state_dir)
        descriptor = _directory_fd(path, create=True)
        try:
            entries = set(os.listdir(descriptor))
            if entries == {MANIFEST_NAME}:
                _read_manifest(descriptor)
                _fixture_catalog()
                return PreviewReport("synthetic.init", "already_initialized", _checks())
            owned = {MARKER_NAME, TEMP_MANIFEST_NAME, MANIFEST_NAME}
            if entries - owned or entries and MARKER_NAME not in entries:
                raise _error(PreviewReason.STATE_INCOMPATIBLE)

            marker_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            if MARKER_NAME not in entries:
                marker = os.open(MARKER_NAME, marker_flags, 0o600, dir_fd=descriptor)
                try:
                    os.fchmod(marker, 0o600)
                    marker_payload = b'{"format_version":1}\n'
                    if os.write(marker, marker_payload) != len(marker_payload):
                        raise OSError(errno.EIO, "short write")
                    os.fsync(marker)
                finally:
                    os.close(marker)
                os.fsync(descriptor)
            elif _managed_file(descriptor, MARKER_NAME, limit=128) != b'{"format_version":1}\n':
                raise _error(PreviewReason.STATE_INCOMPATIBLE)

            _fixture_catalog()
            if MANIFEST_NAME in entries:
                _read_manifest(descriptor)
                if TEMP_MANIFEST_NAME in entries:
                    raise _error(PreviewReason.STATE_INCOMPATIBLE)
            else:
                if TEMP_MANIFEST_NAME not in entries:
                    temporary = os.open(TEMP_MANIFEST_NAME, marker_flags, 0o600, dir_fd=descriptor)
                    try:
                        os.fchmod(temporary, 0o600)
                        payload = _canonical(MANIFEST) + b"\n"
                        written = os.write(temporary, payload)
                        if written != len(payload):
                            raise OSError(errno.EIO, "short write")
                        os.fsync(temporary)
                    finally:
                        os.close(temporary)
                else:
                    _read_exact_manifest(descriptor, TEMP_MANIFEST_NAME)
                os.rename(
                    TEMP_MANIFEST_NAME,
                    MANIFEST_NAME,
                    src_dir_fd=descriptor,
                    dst_dir_fd=descriptor,
                )
                os.fsync(descriptor)
                _read_manifest(descriptor)
            os.unlink(MARKER_NAME, dir_fd=descriptor)
            os.fsync(descriptor)
            return PreviewReport("synthetic.init", "initialized", _checks())
        except SyntheticPreviewError:
            raise
        except FileExistsError:
            raise _error(PreviewReason.STATE_BUSY) from None
        except OSError as error:
            _raise_storage(error)
        finally:
            os.close(descriptor)

    def health(self, state_dir: str) -> PreviewReport:
        path = _validate_absolute(state_dir)
        try:
            descriptor = _directory_fd(path, create=False)
        except SyntheticPreviewError as error:
            if error.reason is PreviewReason.UNSAFE_STORAGE and not path.exists():
                raise _error(PreviewReason.NOT_INITIALIZED) from None
            raise
        try:
            entries = set(os.listdir(descriptor))
            if MARKER_NAME in entries or TEMP_MANIFEST_NAME in entries:
                raise _error(PreviewReason.INITIALIZATION_INCOMPLETE)
            if entries != {MANIFEST_NAME}:
                if not entries:
                    raise _error(PreviewReason.NOT_INITIALIZED)
                raise _error(PreviewReason.STATE_INCOMPATIBLE)
            _read_manifest(descriptor)
            _fixture_catalog()
            return PreviewReport("synthetic.health", "synthetic_ready", _checks())
        finally:
            os.close(descriptor)

    def demo(self, scenario: str) -> DemoReport:
        catalog, digest = _fixture_catalog()
        scenarios = catalog["scenarios"]
        selected = next(
            (item for item in scenarios if isinstance(item, dict) and item.get("name") == scenario),
            None,
        )
        if selected is None:
            raise _error(PreviewReason.USAGE_ERROR)
        steps = selected.get("steps")
        if not isinstance(steps, list) or not steps:
            raise _error(PreviewReason.STATE_INCOMPATIBLE)
        expected_state = "start"
        encountered: set[str] = set()
        for step in steps:
            if (
                not isinstance(step, dict)
                or step.get("from_state") != expected_state
                or not isinstance(step.get("to_state"), str)
                or type(step.get("available_after_seconds")) is not int
                or step["available_after_seconds"] < 0
            ):
                raise _error(PreviewReason.STATE_INCOMPATIBLE)
            expected_state = step["to_state"]
            encountered.add(expected_state)
        last = steps[-1]
        if not isinstance(last, dict) or not isinstance(last.get("to_state"), str):
            raise _error(PreviewReason.STATE_INCOMPATIBLE)
        fixture_result = f"simulated_{last['to_state']}"
        safe_stop_by_state = {
            "not_found": "no_match_observed",
            "ambiguous": "operator_review_required",
            "challenge_captcha": "challenge_not_bypassed",
            "challenge_mfa": "challenge_not_bypassed",
            "outcome_unknown": "retry_prohibited",
            "rate_limited": "rate_limit_respected",
            "schema_drift": "connector_update_required",
            "partial": "operator_review_required",
            "denied": "broker_denial_recorded",
            "resurfaced": "recurrence_observed",
        }
        if "rate_limited" in encountered:
            safe_stop = "rate_limit_respected"
        else:
            safe_stop = safe_stop_by_state.get(last["to_state"], "scenario_complete")
        return DemoReport(
            fixture_result=fixture_result,
            scenario=scenario,
            safe_stop=safe_stop,
            catalog_digest=digest[:12],
        )

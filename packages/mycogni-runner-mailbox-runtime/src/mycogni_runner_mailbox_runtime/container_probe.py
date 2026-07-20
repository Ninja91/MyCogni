"""Synthetic-only executable probe for the runner mailbox OCI artifact.

This is intentionally outside ``services.runner_mailbox``: the mailbox service
has no network/process imports, while this packaging probe must attempt denied
network connections to validate the container boundary.  It is not a service
endpoint and accepts no action or credential input.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import signal
import socket
from importlib import metadata
from pathlib import Path
from typing import NoReturn

from services.runner_mailbox import PersistentMailboxRepository, Sha256CredentialDigester

_SYNTHETIC_MAINTENANCE = b"m" * 32
_SYNTHETIC_STORAGE = b"s" * 32
_SYNTHETIC_INSTALLATION_EPOCH = b"i" * 32
_SYNTHETIC_RESTORE_EPOCH = b"e" * 32
_EXPECTED_DISTRIBUTIONS = [
    "annotated-types",
    "cffi",
    "cryptography",
    "mycogni-connector-sdk",
    "mycogni-runner-mailbox-runtime",
    "pycparser",
    "pydantic",
    "pydantic-core",
    "typing-extensions",
    "typing-inspection",
]


def _alarm(_signum: int, _frame: object) -> NoReturn:
    raise TimeoutError


def _connection_denied(family: socket.AddressFamily, address: tuple[str, int]) -> bool:
    candidate = socket.socket(family)
    try:
        candidate.settimeout(0.25)
        return candidate.connect_ex(address) != 0
    finally:
        candidate.close()


def _dns_denied() -> bool:
    previous = signal.signal(signal.SIGALRM, _alarm)
    signal.setitimer(signal.ITIMER_REAL, 1.0)
    try:
        try:
            socket.getaddrinfo("example.com", 443, type=socket.SOCK_STREAM)
        except (OSError, TimeoutError):
            return True
        return False
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def run(state_path: Path) -> dict[str, object]:
    if os.getuid() != 65532:
        raise RuntimeError("runner probe requires the unprivileged runtime uid")
    status = Path("/proc/self/status").read_text(encoding="utf-8")
    if "Seccomp:\t2\n" not in status:
        raise RuntimeError("runner probe requires an active seccomp filter")
    if Path("/var/run/docker.sock").exists():
        raise RuntimeError("runner probe observed a forbidden Docker socket")
    if importlib.util.find_spec("mycogni") is not None:
        raise RuntimeError("runner artifact contains the forbidden trusted-core package")
    distributions = sorted(
        {
            distribution.metadata["Name"].lower().replace("_", "-")
            for distribution in metadata.distributions()
        }
    )
    if distributions != _EXPECTED_DISTRIBUTIONS:
        raise RuntimeError("runner artifact distribution inventory is unexpected")
    for legal_file in ("LICENSE", "NOTICE"):
        path = Path("/opt/mycogni-runner") / legal_file
        if not path.is_file() or os.access(path, os.W_OK):
            raise RuntimeError("runner artifact legal file is absent or writable")
    if os.access("/opt/mycogni-runner", os.W_OK):
        raise RuntimeError("runner application layer is writable")
    if not os.access(state_path.parent, os.W_OK):
        raise RuntimeError("runner state directory is not writable")

    probes = {
        "dns": _dns_denied(),
        "host_gateway_ipv4": _connection_denied(socket.AF_INET, ("192.168.65.2", 80)),
        "metadata_ipv4": _connection_denied(socket.AF_INET, ("169.254.169.254", 80)),
        "public_ipv4": _connection_denied(socket.AF_INET, ("1.1.1.1", 53)),
        "public_ipv6": _connection_denied(socket.AF_INET6, ("2606:4700:4700::1111", 53)),
        "ula_ipv6": _connection_denied(socket.AF_INET6, ("fd00:ec2::254", 80)),
    }
    if not all(probes.values()):
        raise RuntimeError("runner network containment probe failed")

    digester = Sha256CredentialDigester()
    repository = PersistentMailboxRepository(
        state_path,
        maintenance_credential_digest=digester.digest(_SYNTHETIC_MAINTENANCE),
        storage_key=_SYNTHETIC_STORAGE,
        installation_epoch=_SYNTHETIC_INSTALLATION_EPOCH,
        restore_epoch=_SYNTHETIC_RESTORE_EPOCH,
    )
    repository.close()
    return {
        "mailbox_state_created": state_path.is_file(),
        "installed_distributions": distributions,
        "network_denials": probes,
        "probe": "mycogni.runner_mailbox.container.v1",
        "recovery_required": repository.recovery_required,
        "schema": 1,
        "uid": os.getuid(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--state", required=True, type=Path)
    arguments = parser.parse_args()
    print(json.dumps(run(arguments.state), sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()

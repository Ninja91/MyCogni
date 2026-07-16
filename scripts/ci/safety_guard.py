"""High-confidence repository guard for secrets, PII, and live runtime endpoints."""

from __future__ import annotations

import re
import subprocess
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlparse

REPOSITORY_ROOT = Path(__file__).parents[2]
RUNTIME_ROOTS = ("src/", "packages/", "tests/", "connectors/", "broker-registry/")
SKIP_SUFFIXES = {".lock", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2"}
SECRET_PATTERNS = {
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
}
EMAIL_PATTERN = re.compile(r"(?<![\w.+-])([\w.+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?![\w.-])")
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")
RESERVED_SUFFIXES = (".test", ".example", ".invalid")
RESERVED_HOSTS = {"example.com", "example.net", "example.org", "localhost", "127.0.0.1"}
STATIC_METADATA_HOSTS = {"json-schema.org"}


def tracked_paths() -> list[Path]:
    completed = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
    )
    return [REPOSITORY_ROOT / item.decode() for item in completed.stdout.split(b"\0") if item]


def _is_reserved_host(host: str) -> bool:
    host = host.lower().rstrip(".")
    return host in RESERVED_HOSTS or host.endswith(RESERVED_SUFFIXES)


def scan_paths(paths: Iterable[Path]) -> list[str]:
    errors: list[str] = []
    for path in paths:
        if path.suffix.lower() in SKIP_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        try:
            relative = path.relative_to(REPOSITORY_ROOT).as_posix()
        except ValueError:
            relative = f"tests/{path.name}"
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(text):
                errors.append(f"{relative}: high-confidence {label} pattern")
        if not relative.startswith(RUNTIME_ROOTS):
            continue
        for match in EMAIL_PATTERN.finditer(text):
            if not _is_reserved_host(match.group(2)):
                errors.append(f"{relative}: non-reserved email domain {match.group(2)}")
        for value in URL_PATTERN.findall(text):
            host = urlparse(value.rstrip(".,);]")).hostname
            if host and not (_is_reserved_host(host) or host in STATIC_METADATA_HOSTS):
                errors.append(f"{relative}: live HTTP host {host}")
    return errors


def main() -> int:
    errors = scan_paths(tracked_paths())
    if errors:
        print("\n".join(errors))
        return 1
    print("Safety guard passed: no high-confidence secret, PII, or live runtime endpoint.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Failing canaries for secret, PII, and live-endpoint detection."""

from pathlib import Path

from scripts.ci.safety_guard import scan_paths


def test_guard_rejects_secret_canary(tmp_path: Path) -> None:
    canary = tmp_path / "secret.py"
    # Write the assembled value so the repository never stores a scanner-triggering token.
    canary.write_text("token = '" + "ghp_" + ("A" * 24) + "'\n", encoding="utf-8")
    errors = scan_paths([canary])
    assert any("GitHub token" in error for error in errors)


def test_guard_rejects_non_reserved_identity_and_endpoint(tmp_path: Path) -> None:
    canary = tmp_path / "payload.py"
    email = "person@" + "ordinary-domain.com"
    endpoint = "https://" + "ordinary-domain.com/profile"
    canary.write_text(f"email = {email!r}\nendpoint = {endpoint!r}\n", encoding="utf-8")
    errors = scan_paths([canary])
    assert any("non-reserved email domain" in error for error in errors)
    assert any("live HTTP host" in error for error in errors)


def test_guard_allows_reserved_synthetic_values(tmp_path: Path) -> None:
    fixture = tmp_path / "fixture.py"
    fixture.write_text(
        "email = 'person@broker.example'\nendpoint = 'https://broker.example.test/profile'\n",
        encoding="utf-8",
    )
    assert scan_paths([fixture]) == []

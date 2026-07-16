"""Failing canaries for secret, PII, and live-endpoint detection."""

from pathlib import Path

from scripts.ci.safety_guard import RUNTIME_ROOTS, scan_paths


def test_guard_treats_simulator_as_a_pii_scanned_runtime_surface() -> None:
    assert "simulator/" in RUNTIME_ROOTS


def test_guard_rejects_secret_canary(tmp_path: Path) -> None:
    canary = tmp_path / "secret.py"
    # Write the assembled value so the repository never stores a scanner-triggering token.
    canary.write_text("token = '" + "ghp_" + ("A" * 24) + "'\n", encoding="utf-8")
    errors = scan_paths([canary])
    assert any("GitHub token" in error for error in errors)


def test_guard_scans_lockfiles_for_secret_canaries(tmp_path: Path) -> None:
    canary = tmp_path / "generated.lock"
    canary.write_text("token = '" + "ghp_" + ("B" * 24) + "'\n", encoding="utf-8")
    assert any("GitHub token" in error for error in scan_paths([canary]))


def test_guard_rejects_every_high_confidence_secret_branch(tmp_path: Path) -> None:
    private_key = tmp_path / "private.txt"
    private_key.write_text("-----BEGIN " + "PRIVATE KEY-----\n", encoding="utf-8")
    aws_key = tmp_path / "aws.txt"
    aws_key.write_text("key = '" + "AKIA" + ("A1" * 8) + "'\n", encoding="utf-8")
    errors = scan_paths([private_key, aws_key])
    assert any("private key" in error for error in errors)
    assert any("AWS access key" in error for error in errors)


def test_guard_rejects_non_reserved_identity_and_endpoint(tmp_path: Path) -> None:
    canary = tmp_path / "payload.py"
    email = "person@" + "ordinary-domain.com"
    endpoint = "https://" + "ordinary-domain.com/profile"
    canary.write_text(f"email = {email!r}\nendpoint = {endpoint!r}\n", encoding="utf-8")
    errors = scan_paths([canary])
    assert any("non-reserved email domain" in error for error in errors)
    assert any("live HTTP host" in error for error in errors)


def test_guard_rejects_seeded_direct_identifier_canaries(tmp_path: Path) -> None:
    canary = tmp_path / "identity.py"
    name = "Jane " + "Doe"
    phone = "(415) " + "555-2671"
    ssn = "123-" + "45-6789"
    address = "742 " + "Evergreen Street"
    canary.write_text(
        f"legal_name = {name!r}\nphone = {phone!r}\nssn = {ssn!r}\naddress = {address!r}\n",
        encoding="utf-8",
    )
    errors = scan_paths([canary])
    assert any("labeled personal name" in error for error in errors)
    assert any("US phone number" in error for error in errors)
    assert any("US Social Security number" in error for error in errors)
    assert any("street address" in error for error in errors)


def test_guard_allows_reserved_synthetic_values(tmp_path: Path) -> None:
    fixture = tmp_path / "fixture.py"
    fixture.write_text(
        "email = 'person@broker.example'\nendpoint = 'https://broker.example.test/profile'\n",
        encoding="utf-8",
    )
    assert scan_paths([fixture]) == []

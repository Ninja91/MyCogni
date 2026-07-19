"""Fail closed when the static project walkthrough drifts from repository truth."""

from __future__ import annotations

import hashlib
import re
import sys
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_BLOB_PREFIX = "/Ninja91/MyCogni/blob/main/"


class SiteDocument(HTMLParser):
    """Collect the small structural surface needed for an offline site audit."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.ids: list[str] = []
        self.references: list[tuple[str, str]] = []
        self.elements: list[tuple[str, dict[str, str]]] = []
        self._noscript_depth = 0
        self.noscript_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name: value or "" for name, value in attrs}
        self.elements.append((tag, attributes))
        if identifier := attributes.get("id"):
            self.ids.append(identifier)
        for name in ("href", "src"):
            if reference := attributes.get(name):
                self.references.append((name, reference))
        if tag == "noscript":
            self._noscript_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "noscript":
            self._noscript_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._noscript_depth:
            self.noscript_text.append(data)


def _element_by_id(document: SiteDocument, identifier: str) -> dict[str, str] | None:
    for _tag, attributes in document.elements:
        if attributes.get("id") == identifier:
            return attributes
    return None


def _element_by_class(document: SiteDocument, class_name: str) -> dict[str, str] | None:
    for _tag, attributes in document.elements:
        if class_name in attributes.get("class", "").split():
            return attributes
    return None


def validate_repository(root: Path = ROOT) -> list[str]:
    """Return finite, deterministic validation errors for the checked-out site."""

    errors: list[str] = []
    site = root / "site"
    html_path = site / "index.html"
    css_path = site / "styles.css"
    script_path = site / "app.js"
    matrix_path = root / "docs/v1/COMPLETION_MATRIX.md"
    deployment_path = root / "docs/07-deployment-architecture.md"
    provenance_path = site / "ASSET_PROVENANCE.md"
    site_readme_path = site / "README.md"
    image_path = site / "og.png"

    required_files = (
        html_path,
        css_path,
        script_path,
        matrix_path,
        deployment_path,
        provenance_path,
        site_readme_path,
        image_path,
    )
    for path in required_files:
        if not path.is_file():
            errors.append(f"missing required site input: {path.relative_to(root)}")
    if errors:
        return errors

    html = html_path.read_text(encoding="utf-8")
    css = css_path.read_text(encoding="utf-8")
    script = script_path.read_text(encoding="utf-8")
    matrix = matrix_path.read_text(encoding="utf-8")
    deployment = deployment_path.read_text(encoding="utf-8")
    provenance = provenance_path.read_text(encoding="utf-8")
    site_readme = site_readme_path.read_text(encoding="utf-8")
    document = SiteDocument()
    document.feed(html)

    duplicates = sorted(
        identifier for identifier, count in Counter(document.ids).items() if count > 1
    )
    if duplicates:
        errors.append(f"duplicate HTML ids: {', '.join(duplicates)}")
    identifiers = set(document.ids)

    for kind, reference in document.references:
        parsed = urlparse(reference)
        if reference.startswith("#"):
            if reference[1:] not in identifiers:
                errors.append(f"missing local fragment: {reference}")
            continue
        if parsed.scheme in {"http", "https"}:
            if parsed.netloc == "github.com" and parsed.path.startswith(REPOSITORY_BLOB_PREFIX):
                repository_path = root / unquote(parsed.path.removeprefix(REPOSITORY_BLOB_PREFIX))
                if not repository_path.is_file():
                    errors.append(f"GitHub repository link has no local target: {reference}")
            continue
        if parsed.scheme or reference.startswith("//") or reference.startswith("/"):
            continue
        local_reference = unquote(parsed.path)
        if local_reference and not (site / local_reference).is_file():
            errors.append(f"missing local {kind} asset: {reference}")

    forbidden_status = (
        "The implementation is next",
        "architecture complete",
        "NET-001 remains in remediation review",
    )
    for phrase in forbidden_status:
        if phrase in html:
            errors.append(f"stale project-status phrase: {phrase}")
    required_status = (
        "M0 implementation is in progress",
        "no runnable remover",
        "no accepted deployable image yet",
        "docs/v1/COMPLETION_MATRIX.md",
        "docs/07-deployment-architecture.md",
        'data-project-status="M0_IN_PROGRESS"',
    )
    for phrase in required_status:
        if phrase.lower() not in html.lower():
            errors.append(f"missing current project-status evidence: {phrase}")
    if "| M0 milestone | all M0 | `IN_PROGRESS` |" not in matrix:
        errors.append("completion matrix no longer reports the M0 milestone IN_PROGRESS")

    status_panel = _element_by_class(document, "project-status")
    matrix_statuses = {
        "data-gov-status": r"\| Full traceability validator \| GOV-001 \| `([A-Z_]+)` \|",
        "data-net-status": r"\| Network-deny proof \| NET-001 \| `([A-Z_]+)` \|",
        "data-spikes-status": r"\| Auth/key/egress/runner/browser/backup spikes \| SPIKE-\* \| `([A-Z_]+)` \|",
        "data-sqlite-dur-status": r"\| SQLite/process durability contract \| SQLITE-DUR-001 \| `([A-Z_]+)` \|",
    }
    if status_panel is None:
        errors.append("site has no project-status element")
    else:
        for attribute, pattern in matrix_statuses.items():
            match = re.search(pattern, matrix)
            if not match:
                errors.append(f"completion matrix row is missing for {attribute}")
            elif status_panel.get(attribute) != match.group(1):
                errors.append(
                    f"site {attribute}={status_panel.get(attribute)!r} does not match matrix {match.group(1)!r}"
                )

    deployment_contract = (
        "## Profile A: local-lite",
        "one `mycogni all-in-one` container",
        "periodic rather than continuously busy operation",
    )
    for phrase in deployment_contract:
        if phrase not in deployment:
            errors.append(f"deployment specification lost site-linked contract: {phrase}")
    for phrase in ("Local-lite, single tenant", "all-in-one container", "sporadically on a laptop"):
        if phrase.lower() not in html.lower():
            errors.append(f"site is missing deployment target evidence: {phrase}")

    no_script = " ".join(" ".join(document.noscript_text).split()).lower()
    for heading in (
        "product promise",
        "intended case experience",
        "system authority",
        "failure behavior",
        "delivery path and current status",
    ):
        if heading not in no_script:
            errors.append(f"no-script walkthrough is missing: {heading}")
    for concept in (
        "corroborated verification",
        "connector digest",
        "outcome remains unknown",
        "2–5 capabilities",
        "no runnable remover",
        "stable-cohort evidence",
    ):
        if concept not in no_script:
            errors.append(f"no-script overview is missing substantive concept: {concept}")

    if "ILLUSTRATIVE SYNTHETIC DEMO" not in html:
        errors.append("synthetic console is missing its prominent illustrative badge")

    for identifier in (
        "promise-panel",
        "case-panel",
        "architecture-detail",
        "scenario-answer",
        "phase-panel",
    ):
        attributes = _element_by_id(document, identifier)
        if (
            not attributes
            or attributes.get("aria-live") != "polite"
            or attributes.get("aria-atomic") != "true"
        ):
            errors.append(f"dynamic panel is not an atomic polite live region: {identifier}")
    for _tag, attributes in document.elements:
        if attributes.get("class") == "scenario-list" and attributes.get("role") != "group":
            errors.append("scenario controls must use role=group, not a list without listitems")

    if (
        'setAttribute("aria-current", "location")' not in script
        or 'removeAttribute("aria-current")' not in script
    ):
        errors.append("active chapter navigation does not maintain aria-current")
    if re.search(r"\.chapter-nav\s*\{[^}]*display:\s*none", css, flags=re.DOTALL):
        errors.append("responsive CSS removes chapter navigation without a replacement")
    focus_selectors = (
        ".architecture-section :focus-visible",
        ".phase-panel:focus-visible",
        ".project-status :focus-visible",
        ".deployment-status > div:last-child :focus-visible",
        "footer :focus-visible",
    )
    if (
        any(selector not in css for selector in focus_selectors)
        or "outline-color: var(--lime)" not in css
    ):
        errors.append("dark surfaces do not provide the high-contrast focus treatment")
    if "It is not a `frame-ancestors` or clickjacking control" not in site_readme:
        errors.append("site README does not disclose the meta-CSP framing nonclaim")

    expected_hash_match = re.search(r"SHA-256:\*\* `([0-9a-f]{64})`", provenance)
    if not expected_hash_match:
        errors.append("asset provenance has no parseable og.png SHA-256")
    else:
        actual_hash = hashlib.sha256(image_path.read_bytes()).hexdigest()
        if actual_hash != expected_hash_match.group(1):
            errors.append("og.png SHA-256 does not match ASSET_PROVENANCE.md")

    return errors


def main() -> int:
    errors = validate_repository()
    if errors:
        for error in errors:
            print(f"site_guard: {error}", file=sys.stderr)
        return 1
    print(
        "Site guard passed: status, no-script narrative, links, assets, provenance and accessibility invariants are consistent."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

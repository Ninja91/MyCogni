# Interactive project walkthrough

This directory is a framework-free static walkthrough of the MyCogni architecture and product plan.

- `index.html` contains the narrative and accessible interaction structure.
- `styles.css` contains the responsive visual system.
- `app.js` adds progressive enhancement for the case, architecture, safety, roadmap, navigation, and review interactions; an essential project overview is also present in semantic no-script HTML, while linked specifications remain authoritative and complete.
- `og.png` is the project-specific social preview card.
- `ASSET_PROVENANCE.md` records how the social preview was produced and distributed.
- `.nojekyll` ensures the GitHub Pages artifact is served as authored.

The page uses no analytics, cookies, external fonts, CDN assets, remote APIs, real personal data, or runtime dependencies. Content changes should remain consistent with the authoritative specifications in the repository root and `docs/`.

The meta Content Security Policy disables runtime connections, objects, forms, inline code, and third-party assets. It is not a `frame-ancestors` or clickjacking control because GitHub Pages does not provide project-defined response headers. The current site has no authentication, form, account action, or mutable user state; any future authenticated surface must move behind response-header enforcement.

The GitHub Pages workflow publishes only this directory, but site validation is also triggered when the authoritative completion matrix or deployment specification changes. `scripts/ci/site_guard.py` checks local assets, IDs/fragments, repository links, provenance, no-script coverage, accessibility invariants, and current-status language before upload. Run a local static server rooted at `site/` when checking relative assets; opening `index.html` directly is also supported.

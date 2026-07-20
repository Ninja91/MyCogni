# Browser spike third-party provenance

The repository's original source and documentation remain Apache-2.0. The
browser decision image also contains independently licensed third-party work;
its presence does not relicense those components as MyCogni code.

| Component | Exact input | Upstream/license source |
| --- | --- | --- |
| Playwright OCI base | `mcr.microsoft.com/playwright:v1.61.1-noble@sha256:5b8f294aff9041b7191c34a4bab3ac270157a28774d4b0660e9743297b697e48` | [Playwright v1.61.1](https://github.com/microsoft/playwright/tree/v1.61.1), Apache-2.0 |
| Playwright npm package | `playwright@1.61.1`, integrity locked in `package-lock.json` | [npm registry](https://www.npmjs.com/package/playwright/v/1.61.1), Apache-2.0 |
| Chromium and system libraries | browser revision and packages supplied by the exact OCI base above | licenses/notices embedded by the upstream image; release packaging and complete SBOM/license collection remain `REL-001` work |
| Seccomp baseline | Playwright `v1.61.1/utils/docker/seccomp_profile.json`, then one documented unconditional `chroot` syscall rule for Chromium after its user-namespace transition | [upstream source](https://github.com/microsoft/playwright/blob/v1.61.1/utils/docker/seccomp_profile.json), Apache-2.0 |

This spike is not a redistributable release artifact. Before publication, the
project must produce and review a complete SBOM, license inventory, notices,
signature, and provenance record. The upstream Playwright image is described by
its maintainers as a testing/development image and is not itself treated as a
production security boundary.

The derived image intentionally has no blanket
`org.opencontainers.image.licenses` label. Such a label would inaccurately imply
that the entire image, including Chromium and operating-system packages, is
covered by the repository's Apache-2.0 license. Component-level provenance and
license notices remain the source of truth until `REL-001` produces a reviewed
release inventory.

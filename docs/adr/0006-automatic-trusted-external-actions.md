# ADR-0006: Automatic trusted external actions

- Status: Accepted
- Date: 2026-07-15

## Context

The maintainer selected automatic execution. Hands-off operation is central to the product, but submitting a request can disclose current identity attributes, confirm that a person is active, trigger account/record changes, or target a false match. Connector and legal facts also drift.

## Decision

External actions default globally paused. Onboarding and preview grants cannot enable send. After an exact plan exists, the user may complete a dedicated, non-preselected, step-up ceremony scoped to one capability, destination class, exact-value disclosure ceiling, expiry, pause/challenge and unknown-outcome behavior. MyCogni may automatically submit only when a fresh trusted capability, current authority/policy/match and immutable request plan still fit that automation authorization.

Automation stops and creates a review task for an ambiguous match, new or high-risk attribute, identity document, authorization change, destination/terms/workflow drift, CAPTCHA, MFA, unexpected account control, connector quarantine, policy uncertainty, or unknown prior submission outcome. There is no blanket “send my complete profile to every broker” mode.

## Consequences

- Normal recurring removals are hands-off after setup.
- Setup authorization and connector trust/promotion become high-security product surfaces.
- Each automatic action records the authorization version, plan hash, policy version, connector digest, destination, and disclosed attribute categories.
- Users retain global, profile, and broker kill switches and can revoke future automation.
- Automatic execution must not be described as proof of removal; independent verification semantics remain unchanged.

## Alternatives

Approval for every submission was rejected because it undermines the selected hands-off experience. First-time per-broker approval was rejected as the default but remains available as an optional stricter policy. Unbounded full-profile broadcast was rejected because it increases disclosure and false-match risk.

## Review trigger

Revisit after an unauthorized submission incident, a material change in U.S. authorized-agent requirements, introduction of family/guardian profiles, or any proposal to broaden automatic execution beyond trusted manifest-declared capabilities.

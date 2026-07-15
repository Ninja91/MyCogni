# Trust boundaries and PII flow

```mermaid
flowchart LR
    subgraph z1["Zone 1 — user and trusted UI"]
        entry["Identity entry and setup authorization"]
        preview["Disclosure preview"]
        viewer["Safe evidence viewer"]
    end

    subgraph z2["Zone 2 — trusted core"]
        classify["Attribute classification"]
        decide["Policy decision"]
        ledger["Disclosure ledger"]
        redact["Redaction and report projection"]
    end

    subgraph z3["Zone 3 — vault and keys"]
        sealed[("Field-encrypted PII")]
        evidence[("Encrypted evidence")]
        kek["External key-encryption key"]
    end

    subgraph z4["Zone 4 — isolated connector"]
        action["One action envelope"]
        sandbox["Connector sandbox"]
        session["Connector/profile session state"]
    end

    subgraph z5["Zone 5 — broker network"]
        endpoint["Approved broker endpoint"]
        hostile["Hostile page, email, or response"]
    end

    subgraph z6["Zone 6 — low-trust integrations"]
        assistant["OpenClaw / AI"]
        notifications["Email or chat notifications"]
        diagnostics["Metrics and support bundle"]
    end

    entry -->|"raw attributes over local/TLS channel"| classify
    classify -->|"encrypt by profile and purpose"| sealed
    kek -->|"wrap or unwrap data keys"| sealed
    sealed -->|"only policy-requested attribute types"| decide
    decide -->|"exact proposed bundle"| preview
    preview -->|"setup authorization or exception approval bound to plan hash"| decide
    decide -->|"sealed minimum bundle + expiry"| action
    action --> sandbox
    session --> sandbox
    sandbox -->|"declared fields only"| endpoint
    endpoint --> hostile
    hostile -->|"bounded untrusted bytes"| sandbox
    sandbox -->|"encrypted artifact + structured result"| evidence
    evidence --> viewer
    decide -->|"categories, destination, purpose, time"| ledger
    ledger --> redact
    evidence -->|"local redacted derivative"| redact
    redact -->|"opaque cases, counts, tasks"| assistant
    redact -->|"counts and deep links"| notifications
    redact -->|"allowlisted fields only"| diagnostics

    deny["DENIED: full vault, raw evidence, reusable keys, arbitrary egress"]
    deny -.-> sandbox
    deny -.-> assistant
    deny -.-> diagnostics
```

PII flow is capability-driven. A connector cannot ask the vault for more data; changing its disclosure schema requires a new reviewed connector release and user-visible diff.

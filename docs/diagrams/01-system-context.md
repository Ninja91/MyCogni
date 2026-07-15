# System context

```mermaid
flowchart LR
    user["Person protecting their data"]
    household["Authorized household member"]
    maintainer["Connector and policy maintainer"]
    operator["Self-hosting operator"]

    mycogni["MyCogni<br/>personal data-rights orchestrator"]

    publicBroker["Public people-search sites"]
    privateBroker["Private data brokers"]
    registry["Government and open broker registries"]
    mail["User-controlled email provider"]
    official["Official privacy portals<br/>such as California DROP"]
    secret["OS keychain or cloud secret manager"]
    assistant["Personal OpenClaw or assistant"]
    notify["Notification channel"]

    user -->|"identity, setup authorization, exception reviews"| mycogni
    mycogni -->|"findings, evidence, tasks, reports"| user
    household -->|"separately scoped authorization"| mycogni
    maintainer -->|"signed connector and policy updates"| mycogni
    operator -->|"deploy, backup, restore, upgrade"| mycogni

    mycogni -->|"read-only observation and setup-authorized minimum-disclosure requests"| publicBroker
    mycogni -->|"setup-authorized request; verification may be unavailable"| privateBroker
    mycogni -->|"public metadata with provenance"| registry
    mycogni <-->|"drafts, authorized sends, correlated replies"| mail
    mycogni -->|"guided task and completion record"| official
    secret -->|"key-encryption key or unwrap operation"| mycogni
    assistant -->|"metadata-only tools by default"| mycogni
    mycogni -->|"PII-free counts and deep links"| notify

    note["No broker, registry, notification, or assistant receives the complete identity profile"]
    note -.-> mycogni
```

Context invariants:

- A household member does not inherit another profile's authority.
- Official portal identity controls are user-completed, not bypassed.
- Assistant and notification surfaces are outside the PII trust boundary.

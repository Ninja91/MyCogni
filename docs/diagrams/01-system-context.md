# System context

```mermaid
flowchart LR
    user["Consenting U.S. adult"]
    maintainer["Connector, policy, and security maintainer"]
    operator["Self-hosting operator"]

    mycogni["MyCogni<br/>proof-first data-rights orchestrator"]

    publicBroker["Public people-search sites"]
    privateBroker["Private data brokers"]
    registry["Government and licensed public sources"]
    mail["User-controlled mail provider"]
    official["Official privacy portals<br/>such as California DROP"]
    secret["OS keychain or cloud KMS/secret manager"]
    assistant["Personal OpenClaw instance"]
    localModel["Optional local model runtime<br/>post-v1 advisory only"]
    notify["PII-free notification channel"]

    user -->|"identity, setup authorization, exception review"| mycogni
    mycogni -->|"exposure, disclosure, evidence, tasks, reports"| user
    maintainer -->|"reviewed versioned connector and policy releases"| mycogni
    operator -->|"deploy, key recovery, backup, restore, upgrade"| mycogni

    mycogni -->|"read-only observation and trusted minimum-disclosure requests"| publicBroker
    mycogni -->|"only sourced and authorized workflows"| privateBroker
    mycogni -->|"public facts with provenance/license/expiry"| registry
    mycogni <-->|"drafts, exact authorized sends, correlated replies"| mail
    mycogni -->|"guided user-completed flow and completion record"| official
    secret -->|"wrap or unwrap independent profile keys"| mycogni
    assistant -->|"metadata-only tools by default"| mycogni
    mycogni -.->|"sanitized bounded task; no tools"| localModel
    localModel -.->|"untrusted suggestion only"| mycogni
    mycogni -->|"counts, reason codes, deep links"| notify

    note["No broker, registry, notification, assistant, or model receives the complete identity profile"]
    note -.-> mycogni
```

Context invariants:

- Stable v1 supports one consenting adult per installation; later profiles remain separately authorized.
- Official identity controls are user-completed, never bypassed.
- OpenClaw and optional local intelligence have no default vault, approval, or submission authority.
- “Supported” means a capability with visible maturity/freshness, not a broker metadata row.

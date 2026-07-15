# Container and component architecture

```mermaid
flowchart TB
    subgraph control["Authenticated user control plane"]
        ui["Local web UI<br/>server-rendered FastAPI"]
        cli["CLI over permissioned authenticated channel"]
        session["Bootstrap, session, step-up, authority epochs"]
    end

    subgraph core["Trusted deterministic core image"]
        api["Command and Query API"]
        identity["Identity Vault + key catalog"]
        registry["Broker Registry"]
        discovery["Discovery"]
        cases["Case Management"]
        policy["Policy and Disclosure Engine"]
        journal["External Intent Journal"]
        orchestrator["Jobs, leases, outbox, catch-up"]
        budget["Resource Budget Manager"]
        evidenceSvc["Evidence and verification service"]
        reporting["Reporting + support matrix"]
        integration["Mail / OpenClaw gateway"]
        taskBuilder["Deterministic intelligence task builder"]
    end

    subgraph state["Encrypted state and recovery boundary"]
        db[("SQLite local-lite<br/>PostgreSQL cloud-small")]
        objects[("Encrypted evidence objects")]
        keyCatalog[("Wrapped random profile-key catalog")]
        kek["External KEK provider"]
        checkpoint["External monotonic integrity checkpoint"]
    end

    subgraph execution["Separate untrusted artifacts"]
        connector["Digest-pinned connector OCI/WASI artifact"]
        browser["Ephemeral Playwright/Chromium artifact"]
        envelope["One-time sealed action + fence"]
        egress["Mandatory egress policy gateway"]
    end

    subgraph advisory["Optional post-v1 local intelligence"]
        nullAdapter["IntelligencePort<br/>null by default"]
        localRunner["Isolated local runtime<br/>no network, tools, vault, or DB"]
        suggestion["Schema + span validated<br/>UntrustedSuggestion"]
    end

    subgraph external["External and hostile"]
        broker["Manifest-approved broker origin"]
        mail["Mail provider"]
        sources["Registry / policy sources"]
        openclaw["OpenClaw / assistant"]
    end

    ui --> api
    cli --> api
    session --> api
    api --> identity
    api --> registry
    api --> discovery
    api --> cases
    api --> reporting
    api --> integration
    discovery --> policy
    cases --> policy
    policy --> journal
    journal --> orchestrator
    discovery --> orchestrator
    orchestrator --> budget

    identity <-->|"encrypted profile data"| db
    cases <-->|"events, projections, intents"| db
    orchestrator <-->|"jobs, leases, outbox"| db
    identity <-->|"wrapped profile keys"| keyCatalog
    kek -->|"wrap/unwrap only"| keyCatalog
    evidenceSvc <-->|"encrypted locators and hashes"| db
    evidenceSvc <-->|"bounded objects"| objects
    evidenceSvc --> checkpoint
    reporting --> db

    orchestrator -->|"issue current fence"| envelope
    envelope --> connector
    envelope --> browser
    connector -->|"all outbound bytes"| egress
    browser -->|"all outbound bytes"| egress
    egress <-->|"validated connection"| broker
    connector -->|"structured result + evidence"| evidenceSvc
    browser -->|"result or human task"| evidenceSvc
    evidenceSvc --> cases

    integration <-->|"scoped mail credential"| mail
    registry -->|"licensed/provenanced public facts"| sources
    integration <-->|"metadata-only tools"| openclaw

    cases -.-> taskBuilder
    taskBuilder -.->|"sanitized bounded task"| nullAdapter
    nullAdapter -.-> localRunner
    localRunner -.-> suggestion
    suggestion -.->|"advisory display/review only"| cases
    budget -.-> localRunner

    guard["Core contains no connector, browser, model runtime, or model weights"]
    guard -.-> core
```

The core image can co-locate trusted roles in local-lite. Runtime boundaries, authentication, gateway enforcement, key separation, and authority semantics remain intact.

# Deployment profiles

```mermaid
flowchart TB
    subgraph local["Local-lite — one adult, laptop/NAS/home server"]
        browserClient["Authenticated localhost browser"] --> coreLocal["Core all-in-one image<br/>serve + worker + scheduler"]
        cli["CLI via permissioned local channel"] --> coreLocal
        coreLocal --> sqlite[("SQLite metadata<br/>field/relationship encryption")]
        coreLocal --> files[("Encrypted evidence volume")]
        hostKEK["Explicit local KEK profile<br/>owner-file baseline; Keychain or key-volume pending"] --> keyCatalog[("Separate wrapped-profile-key catalog")]
        keyCatalog --> coreLocal
        coreLocal --> budget["One heavy-work lease"]
        budget -.-> connectorLocal["Ephemeral digest-pinned connector artifact"]
        budget -.-> browserLocal["Ephemeral Playwright artifact"]
        connectorLocal --> gatewayLocal["Mandatory egress gateway"]
        browserLocal --> gatewayLocal
        gatewayLocal --> internetLocal["Approved public broker origins"]
        coreLocal -.-> taskLocal["Sanitized advisory task"]
        taskLocal -.-> modelLocal["Optional post-v1 local model<br/>separate, no network"]
    end

    subgraph cloud["Cloud-small — single tenant"]
        client["User browser"] --> ingress["TLS ingress + passkey/OIDC"]
        ingress --> serve["Core image: serve role"]
        scheduler["Core image: scheduler leader"] --> pg[("Private PostgreSQL")]
        serve --> pg
        worker1["Core image: worker role"] --> pg
        worker2["Optional core worker"] --> pg
        serve --> object[("Encrypted evidence objects")]
        worker1 --> object
        kms["KMS/secret manager KEK"] --> cloudCatalog[("Separate wrapped-profile-key catalog")]
        cloudCatalog --> serve
        cloudCatalog --> worker1
        worker1 --> cloudConnector["Isolated connector job/artifact"]
        worker1 --> cloudBrowser["Isolated browser job/artifact"]
        cloudConnector --> cloudGateway["Mandatory egress gateway"]
        cloudBrowser --> cloudGateway
        cloudGateway --> internetCloud["Approved public broker origins"]
        higher["Optional gVisor/Kata/VM higher-assurance tier"] -.-> cloudConnector
        higher -.-> cloudBrowser
    end

    updates["Expiring monotonic signed registry + artifact provenance"] -.->|"explicit verified update"| coreLocal
    updates -.->|"explicit verified update"| serve

    warning["Same domain semantics, separate conformance and assurance claims<br/>Never multi-tenant SaaS"]
    warning -.-> coreLocal
    warning -.-> serve
```

The core, connector, browser, gateway, and optional model are distinct artifacts/processes. Local shared-kernel isolation is explicitly lower assurance than a hardened cloud sandbox. Active model resources are excluded from core idle claims and are never required.

This is a target-profile diagram. The native POSIX-mode owner-file source has source/fixture
evidence only. A macOS Security.framework helper cannot be called directly from the Linux
container; a container key-only volume needs separate rootless Linux Engine and Docker Desktop
evidence; cloud KMS is post-v1. None is inferred from the others.

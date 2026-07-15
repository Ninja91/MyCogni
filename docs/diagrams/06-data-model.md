# Core data model

```mermaid
erDiagram
    ACTOR ||--o{ SESSION : authenticates
    ACTOR ||--o{ AUTHORITY_GRANT : holds
    PROFILE ||--o{ AUTHORITY_GRANT : represented_by
    PROFILE ||--|| PROFILE_KEY : encrypted_by
    KEY_CATALOG_BACKUP ||--o{ PROFILE_KEY : may_recover
    PROFILE ||--o{ IDENTITY_ATTRIBUTE : owns
    PROFILE ||--o{ AUTHORIZATION : grants
    PROFILE ||--o{ OBSERVATION_RUN : scopes
    PROFILE ||--o{ CASE : scopes

    BROKER ||--o{ BROKER_ENDPOINT : exposes
    BROKER ||--o{ CONNECTOR_RELEASE : automated_by
    CONNECTOR_RELEASE ||--|| CONNECTOR_ARTIFACT : built_as
    CONNECTOR_RELEASE ||--o{ DISCLOSURE_SCHEMA : declares
    CONNECTOR_RELEASE ||--o{ OBSERVATION_RUN : executes

    OBSERVATION_RUN ||--o{ FINDING : produces
    FINDING o|--o| CASE : confirms_into
    CASE ||--o{ REQUEST_PLAN : versions
    REQUEST_PLAN ||--o{ AUTHORIZATION : covered_by
    REQUEST_PLAN ||--o{ EXTERNAL_INTENT : creates
    EXTERNAL_INTENT ||--o{ SUBMISSION_ATTEMPT : executes
    CASE ||--o{ VERIFICATION : checks
    CASE ||--o{ RESURFACING_OCCURRENCE : detects
    CASE ||--o{ TASK : blocks_on
    CASE ||--o{ CASE_EVENT : sources
    CASE_EVENT }o--|| INTEGRITY_CHECKPOINT : anchored_by
    CASE ||--o{ ADVISORY_SUGGESTION : may_display

    FINDING ||--o{ EVIDENCE_OBJECT : supports
    SUBMISSION_ATTEMPT ||--o{ EVIDENCE_OBJECT : supports
    VERIFICATION ||--o{ EVIDENCE_OBJECT : supports

    PROFILE {
        uuid id
        string jurisdiction
        string lifecycle
    }
    PROFILE_KEY {
        uuid profile_id
        bytes wrapped_random_dek
        int version
        string state
    }
    AUTHORITY_GRANT {
        uuid actor_id
        uuid profile_id
        string scope
        int revocation_epoch
        datetime expires_at
    }
    CONNECTOR_RELEASE {
        uuid id
        string version
        string capability_maturity
        datetime expires_at
    }
    CONNECTOR_ARTIFACT {
        string digest
        string runtime_class
        string provenance_ref
        string revocation_state
    }
    CASE {
        uuid id
        uuid profile_id
        uuid broker_id
        string intent
        string status_projection
    }
    REQUEST_PLAN {
        uuid id
        uuid case_id
        string plan_hash
        string policy_version
        bytes sealed_payload
    }
    EXTERNAL_INTENT {
        uuid intent_id
        uuid plan_id
        bigint current_fence
        string journal_state
    }
    SUBMISSION_ATTEMPT {
        uuid attempt_id
        uuid intent_id
        bigint fence
        string connector_digest
        string result
    }
    VERIFICATION {
        uuid case_id
        string method
        string assurance
        datetime observed_at
    }
    ADVISORY_SUGGESTION {
        uuid case_id
        string task_type
        string artifact_digest
        string validation
        datetime expires_at
    }
```

Readable PII is absent from relational fields. The wrapped-key catalog is a separate recovery asset. An advisory suggestion is encrypted, expiring, and never a domain event or decision source.

"""Seeded synthetic identities with canonical serialization and hashing."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any

from simulator.protocol import is_reserved_mailbox

CORPUS_SCHEMA = "mycogni.synthetic-corpus.v1"
DEFAULT_SEED = "mycogni-sim-001-seed-v1"
GIVEN_TOKENS = ("Aster", "Bramble", "Cinder", "Dapple", "Ember", "Fable")
FAMILY_TOKENS = ("Quill", "Rook", "Thistle", "Vellum", "Wisp", "Yarrow")
REGION_TOKENS = ("Example North", "Example South", "Fixture East", "Fixture West")


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _index(seed: str, record: int, label: str, size: int) -> int:
    digest = hashlib.sha256(f"{seed}:{record}:{label}".encode()).digest()
    return int.from_bytes(digest[:8], "big") % size


@dataclass(frozen=True, slots=True)
class SyntheticIdentity:
    identity_id: str
    fictional_name: str
    mailbox: str
    contact_token: str
    region_label: str
    fictional: bool = True

    def __post_init__(self) -> None:
        if not self.fictional:
            raise ValueError("synthetic corpus identities must be marked fictional")
        if not is_reserved_mailbox(self.mailbox):
            raise ValueError("synthetic mailbox must use a reserved domain")


@dataclass(frozen=True, slots=True)
class SyntheticCorpus:
    schema: str
    seed: str
    identities: tuple[SyntheticIdentity, ...]
    canonical_hash: str

    def payload(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "seed": self.seed,
            "identities": [asdict(identity) for identity in self.identities],
        }

    def verify(self) -> None:
        actual = hashlib.sha256(canonical_json(self.payload())).hexdigest()
        if actual != self.canonical_hash:
            raise ValueError("synthetic corpus canonical hash mismatch")

    def canonical_document(self) -> bytes:
        self.verify()
        return canonical_json({**self.payload(), "canonical_hash": self.canonical_hash}) + b"\n"


def build_corpus(*, seed: str = DEFAULT_SEED, count: int = 6) -> SyntheticCorpus:
    if not seed or len(seed.encode()) > 128:
        raise ValueError("corpus seed must contain 1 to 128 UTF-8 bytes")
    if not 1 <= count <= 32:
        raise ValueError("corpus identity count must be between 1 and 32")
    identities = tuple(
        SyntheticIdentity(
            identity_id=f"fictional-{record:03d}",
            fictional_name=(
                f"{GIVEN_TOKENS[_index(seed, record, 'given', len(GIVEN_TOKENS))]} "
                f"{FAMILY_TOKENS[_index(seed, record, 'family', len(FAMILY_TOKENS))]}"
            ),
            mailbox=f"fictional-{record:03d}@identity.test",
            contact_token=f"non-dialable-contact-{record:03d}",
            region_label=REGION_TOKENS[_index(seed, record, "region", len(REGION_TOKENS))],
        )
        for record in range(count)
    )
    payload = {
        "schema": CORPUS_SCHEMA,
        "seed": seed,
        "identities": [asdict(identity) for identity in identities],
    }
    corpus = SyntheticCorpus(
        schema=CORPUS_SCHEMA,
        seed=seed,
        identities=identities,
        canonical_hash=hashlib.sha256(canonical_json(payload)).hexdigest(),
    )
    corpus.verify()
    return corpus

"""Reviewed synthetic identities with canonical serialization and hashing."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from enum import IntEnum
from typing import Any

from simulator.protocol import is_reserved_mailbox

CORPUS_SCHEMA = "mycogni.synthetic-corpus.v2"
MAX_IDENTITIES = 32
IDENTITY_ID = re.compile(r"fictional-[0-9]{3}")
CONTACT_TOKEN = re.compile(r"non-dialable-contact-[0-9]{3}")
GIVEN_TOKENS = ("Aster", "Bramble", "Cinder", "Dapple", "Ember", "Fable")
FAMILY_TOKENS = ("Quill", "Rook", "Thistle", "Vellum", "Wisp", "Yarrow")
REGION_TOKENS = ("Example North", "Example South", "Fixture East", "Fixture West")


class CorpusSeedID(IntEnum):
    BASELINE_V1 = 1
    ALTERNATE_V1 = 2


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate corpus key: {key}")
        result[key] = value
    return result


@dataclass(frozen=True, slots=True, init=False)
class _SyntheticIdentity:
    identity_id: str
    fictional_name: str
    mailbox: str
    contact_token: str
    region_label: str
    fictional: bool

    @classmethod
    def _generated(
        cls,
        *,
        record: int,
        fictional_name: str,
        region_label: str,
    ) -> _SyntheticIdentity:
        instance = object.__new__(cls)
        object.__setattr__(instance, "identity_id", f"fictional-{record:03d}")
        object.__setattr__(instance, "fictional_name", fictional_name)
        object.__setattr__(instance, "mailbox", f"fictional-{record:03d}@identity.test")
        object.__setattr__(instance, "contact_token", f"non-dialable-contact-{record:03d}")
        object.__setattr__(instance, "region_label", region_label)
        object.__setattr__(instance, "fictional", True)
        instance._validate()
        return instance

    def _validate(self) -> None:
        if not self.fictional:
            raise ValueError("synthetic identity must be marked fictional")
        if not IDENTITY_ID.fullmatch(self.identity_id):
            raise ValueError("synthetic identity ID is outside the closed grammar")
        suffix = self.identity_id.removeprefix("fictional-")
        if self.mailbox != f"fictional-{suffix}@identity.test" or not is_reserved_mailbox(
            self.mailbox
        ):
            raise ValueError("synthetic mailbox is outside the generated reserved grammar")
        if self.contact_token != f"non-dialable-contact-{suffix}" or not CONTACT_TOKEN.fullmatch(
            self.contact_token
        ):
            raise ValueError("synthetic contact token is outside the closed grammar")
        given, separator, family = self.fictional_name.partition(" ")
        if not separator or given not in GIVEN_TOKENS or family not in FAMILY_TOKENS:
            raise ValueError("synthetic name is outside the reviewed fictional lexicon")
        if self.region_label not in REGION_TOKENS:
            raise ValueError("synthetic region is outside the reviewed fixture lexicon")


@dataclass(frozen=True, slots=True, init=False)
class SyntheticCorpus:
    schema: str
    seed_id: CorpusSeedID
    identities: tuple[_SyntheticIdentity, ...]
    canonical_hash: str

    @classmethod
    def _generated(
        cls,
        *,
        seed_id: CorpusSeedID,
        identities: tuple[_SyntheticIdentity, ...],
        canonical_hash: str,
    ) -> SyntheticCorpus:
        instance = object.__new__(cls)
        object.__setattr__(instance, "schema", CORPUS_SCHEMA)
        object.__setattr__(instance, "seed_id", seed_id)
        object.__setattr__(instance, "identities", identities)
        object.__setattr__(instance, "canonical_hash", canonical_hash)
        instance.verify()
        return instance

    def payload(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "seed_id": int(self.seed_id),
            "identities": [asdict(identity) for identity in self.identities],
        }

    def verify(self) -> None:
        if self.schema != CORPUS_SCHEMA or type(self.seed_id) is not CorpusSeedID:
            raise ValueError("synthetic corpus schema or reviewed seed ID is invalid")
        if not 1 <= len(self.identities) <= MAX_IDENTITIES:
            raise ValueError("synthetic corpus size is outside the reviewed cap")
        for identity in self.identities:
            identity._validate()
        identity_ids = {identity.identity_id for identity in self.identities}
        names = {identity.fictional_name for identity in self.identities}
        mailboxes = {identity.mailbox for identity in self.identities}
        contacts = {identity.contact_token for identity in self.identities}
        expected_count = len(self.identities)
        if any(
            len(values) != expected_count for values in (identity_ids, names, mailboxes, contacts)
        ):
            raise ValueError("synthetic corpus identity fields must be unique")
        actual = hashlib.sha256(canonical_json(self.payload())).hexdigest()
        if actual != self.canonical_hash:
            raise ValueError("synthetic corpus canonical hash mismatch")

    def canonical_document(self) -> bytes:
        self.verify()
        return canonical_json({**self.payload(), "canonical_hash": self.canonical_hash}) + b"\n"

    @classmethod
    def parse_canonical_document(cls, document: bytes) -> SyntheticCorpus:
        try:
            value = json.loads(document.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("synthetic corpus document is not canonical JSON") from error
        if not isinstance(value, dict) or set(value) != {
            "canonical_hash",
            "identities",
            "schema",
            "seed_id",
        }:
            raise ValueError("synthetic corpus document has an unknown or missing field")
        seed_value = value["seed_id"]
        identities = value["identities"]
        if type(seed_value) is not int or not isinstance(identities, list):
            raise ValueError("synthetic corpus document has invalid field types")
        try:
            seed_id = CorpusSeedID(seed_value)
        except ValueError as error:
            raise ValueError("synthetic corpus document uses an unreviewed seed ID") from error
        expected = build_corpus(seed_id=seed_id, count=len(identities))
        if document != expected.canonical_document():
            raise ValueError("synthetic corpus document differs from generated canonical corpus")
        return expected


def _ordered_names(seed_id: CorpusSeedID) -> list[str]:
    names = [f"{given} {family}" for given in GIVEN_TOKENS for family in FAMILY_TOKENS]
    return sorted(
        names,
        key=lambda name: hashlib.sha256(f"{int(seed_id)}:{name}".encode()).digest(),
    )


def build_corpus(
    *,
    seed_id: CorpusSeedID = CorpusSeedID.BASELINE_V1,
    count: int = 6,
) -> SyntheticCorpus:
    if type(seed_id) is not CorpusSeedID:
        raise ValueError("corpus seed must be a reviewed CorpusSeedID")
    if type(count) is not int or not 1 <= count <= MAX_IDENTITIES:
        raise ValueError("corpus identity count is outside the reviewed cap")
    ordered_names = _ordered_names(seed_id)
    identities = tuple(
        _SyntheticIdentity._generated(
            record=record,
            fictional_name=ordered_names[record],
            region_label=REGION_TOKENS[(record + int(seed_id) - 1) % len(REGION_TOKENS)],
        )
        for record in range(count)
    )
    payload = {
        "schema": CORPUS_SCHEMA,
        "seed_id": int(seed_id),
        "identities": [asdict(identity) for identity in identities],
    }
    return SyntheticCorpus._generated(
        seed_id=seed_id,
        identities=identities,
        canonical_hash=hashlib.sha256(canonical_json(payload)).hexdigest(),
    )

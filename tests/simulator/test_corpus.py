from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest
from hypothesis import given
from hypothesis import strategies as st

import simulator
from simulator.corpus import CorpusSeedID, SyntheticCorpus, build_corpus, canonical_json

FIXTURES = Path(__file__).parents[2] / "simulator/fixtures"


def test_default_corpus_matches_and_parses_canonical_golden_fixture() -> None:
    document = (FIXTURES / "corpus.v2.json").read_bytes()
    corpus = build_corpus()
    assert corpus.canonical_document() == document
    assert SyntheticCorpus.parse_canonical_document(document) == corpus
    assert all(identity.fictional for identity in corpus.identities)
    assert len({identity.fictional_name for identity in corpus.identities}) == len(
        corpus.identities
    )


@given(
    seed_id=st.sampled_from(tuple(CorpusSeedID)),
    count=st.integers(min_value=1, max_value=32),
)
def test_reviewed_seed_id_and_count_fully_determine_corpus(
    seed_id: CorpusSeedID, count: int
) -> None:
    first = build_corpus(seed_id=seed_id, count=count)
    second = build_corpus(seed_id=seed_id, count=count)
    assert first == second
    assert first.canonical_document() == second.canonical_document()


@pytest.mark.parametrize("seed", [0, 3, "user-selected", True])
def test_arbitrary_seed_mutations_are_rejected(seed: object) -> None:
    with pytest.raises(ValueError, match="reviewed CorpusSeedID"):
        build_corpus(seed_id=cast(CorpusSeedID, seed))


def test_identity_has_no_public_unsafe_constructor_or_export() -> None:
    assert "SyntheticIdentity" not in simulator.__all__
    assert not hasattr(simulator, "SyntheticIdentity")


def _mutated_document(mutate: Any) -> bytes:
    document = json.loads(build_corpus().canonical_document())
    mutate(document)
    return canonical_json(document) + b"\n"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("fictional_name", "John" + " Smith"),
        ("mailbox", "person@" + "public" + ".com"),
        ("contact_token", "+1-" + "415-" + "555-2671"),
        ("region_label", "742" + " Evergreen Street"),
    ],
)
def test_real_looking_identity_field_mutations_are_rejected(field: str, value: str) -> None:
    mutation = _mutated_document(
        lambda document: document["identities"][0].__setitem__(field, value)
    )
    with pytest.raises(ValueError, match="differs from generated canonical corpus"):
        SyntheticCorpus.parse_canonical_document(mutation)


def test_secret_and_unknown_field_mutation_is_rejected() -> None:
    secret = "ghp_" + ("A" * 24)
    mutation = _mutated_document(
        lambda document: document["identities"][0].__setitem__("secret", secret)
    )
    with pytest.raises(ValueError, match="differs from generated canonical corpus"):
        SyntheticCorpus.parse_canonical_document(mutation)


def test_duplicate_identity_mutation_is_rejected() -> None:
    def duplicate(document: dict[str, Any]) -> None:
        document["identities"][1] = document["identities"][0]

    with pytest.raises(ValueError, match="differs from generated canonical corpus"):
        SyntheticCorpus.parse_canonical_document(_mutated_document(duplicate))


def test_duplicate_json_key_is_rejected() -> None:
    mutation = b'{"schema":"one","schema":"two"}\n'
    with pytest.raises(ValueError, match="duplicate corpus key"):
        SyntheticCorpus.parse_canonical_document(mutation)


def test_unreviewed_seed_document_is_rejected() -> None:
    mutation = _mutated_document(lambda document: document.__setitem__("seed_id", 99))
    with pytest.raises(ValueError, match="unreviewed seed ID"):
        SyntheticCorpus.parse_canonical_document(mutation)

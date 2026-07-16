from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from simulator.corpus import SyntheticCorpus, SyntheticIdentity, build_corpus

FIXTURES = Path(__file__).parents[2] / "simulator/fixtures"


def test_default_corpus_matches_canonical_golden_fixture() -> None:
    corpus = build_corpus()
    assert corpus.canonical_document() == (FIXTURES / "corpus.v1.json").read_bytes()
    assert all(identity.fictional for identity in corpus.identities)
    assert all(identity.mailbox.endswith(".test") for identity in corpus.identities)


@given(
    seed=st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789-", min_size=1, max_size=40),
    count=st.integers(min_value=1, max_value=32),
)
def test_seed_and_count_fully_determine_corpus(seed: str, count: int) -> None:
    first = build_corpus(seed=seed, count=count)
    second = build_corpus(seed=seed, count=count)
    assert first == second
    assert first.canonical_document() == second.canonical_document()


def test_corpus_hash_detects_mutated_generated_data() -> None:
    corpus = build_corpus()
    changed = replace(corpus.identities[0], fictional_name="Mutation Canary")
    mutation = SyntheticCorpus(
        corpus.schema,
        corpus.seed,
        (changed, *corpus.identities[1:]),
        corpus.canonical_hash,
    )
    with pytest.raises(ValueError, match="canonical hash mismatch"):
        mutation.verify()


def test_non_reserved_mailbox_mutation_fails_closed() -> None:
    non_reserved = "fictional@" + "public" + ".com"
    with pytest.raises(ValueError, match="reserved domain"):
        SyntheticIdentity(
            identity_id="fictional-mutation",
            fictional_name="Mutation Canary",
            mailbox=non_reserved,
            contact_token="non-dialable-contact-mutation",
            region_label="Fixture Mutation",
        )


@pytest.mark.parametrize("mailbox", ["missing-at.test", "two@@identity.test", "@identity.test"])
def test_malformed_reserved_mailbox_mutations_fail_closed(mailbox: str) -> None:
    with pytest.raises(ValueError, match="reserved domain"):
        SyntheticIdentity(
            identity_id="fictional-mutation",
            fictional_name="Mutation Canary",
            mailbox=mailbox,
            contact_token="non-dialable-contact-mutation",
            region_label="Fixture Mutation",
        )

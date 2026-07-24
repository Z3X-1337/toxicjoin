from __future__ import annotations

import pytest

from toxicjoin.context.datahub import DataHubMetadataError, _normalize_field
from toxicjoin.models import SensitivityCategory


def test_edited_tag_alone_classifies_sensitive_field() -> None:
    field = {
        "fieldPath": "churn_score",
        "editedTags": {
            "tags": [
                {"tag": {"urn": "urn:li:tag:toxicjoin:model-output"}},
            ]
        },
    }

    normalized = _normalize_field(field)

    assert normalized.category == SensitivityCategory.SENSITIVE_ATTRIBUTE
    assert normalized.tags == ("urn:li:tag:toxicjoin:model-output",)


def test_edited_glossary_term_alone_classifies_stable_pseudonym() -> None:
    field = {
        "fieldPath": "customer_id",
        "editedGlossaryTerms": {
            "terms": [
                {
                    "term": {
                        "urn": (
                            "urn:li:glossaryTerm:"
                            "StableCustomerIdentifier"
                        )
                    }
                }
            ]
        },
    }

    normalized = _normalize_field(field)

    assert normalized.category == SensitivityCategory.STABLE_PSEUDONYM
    assert normalized.glossary_terms == (
        "urn:li:glossaryTerm:StableCustomerIdentifier",
    )


def test_system_and_edited_metadata_are_merged_and_deduplicated() -> None:
    field = {
        "fieldPath": "precise_area",
        "tags": {
            "tags": [
                {"tag": {"urn": "urn:li:tag:toxicjoin:quasi-identifier"}},
            ]
        },
        "editedTags": [
            {"tag": {"urn": "urn:li:tag:toxicjoin:quasi-identifier"}},
        ],
        "edited_glossary_terms": {
            "terms": [
                {"term": {"name": "Quasi Identifier"}},
            ]
        },
    }

    normalized = _normalize_field(field)

    assert normalized.category == SensitivityCategory.QUASI_IDENTIFIER
    assert normalized.tags == (
        "urn:li:tag:toxicjoin:quasi-identifier",
    )
    assert normalized.glossary_terms == ("Quasi Identifier",)


def test_cleaned_mcp_string_tag_entry_is_supported() -> None:
    field = {
        "fieldPath": "age_band",
        "tags": ["urn:li:tag:toxicjoin:quasi-identifier"],
    }

    normalized = _normalize_field(field)

    assert normalized.category == SensitivityCategory.QUASI_IDENTIFIER
    assert normalized.tags == (
        "urn:li:tag:toxicjoin:quasi-identifier",
    )


def test_cleaned_mcp_string_glossary_entry_is_supported() -> None:
    field = {
        "fieldPath": "customer_id",
        "editedGlossaryTerms": {
            "terms": ["urn:li:glossaryTerm:StableCustomerIdentifier"],
        },
    }

    normalized = _normalize_field(field)

    assert normalized.category == SensitivityCategory.STABLE_PSEUDONYM
    assert normalized.glossary_terms == (
        "urn:li:glossaryTerm:StableCustomerIdentifier",
    )


def test_conflicting_system_and_edited_categories_fail_closed() -> None:
    field = {
        "fieldPath": "case_category",
        "tags": {
            "tags": [
                {"tag": {"urn": "urn:li:tag:toxicjoin:public-or-low-risk"}},
            ]
        },
        "editedTags": {
            "tags": [
                {"tag": {"urn": "urn:li:tag:toxicjoin:sensitive-support"}},
            ]
        },
    }

    with pytest.raises(DataHubMetadataError, match="conflicting sensitivity categories"):
        _normalize_field(field)


def test_malformed_edited_metadata_fails_closed() -> None:
    field = {
        "fieldPath": "customer_id",
        "editedTags": {"tags": "not-a-list"},
    }

    with pytest.raises(DataHubMetadataError, match="invalid editedTags.tags metadata"):
        _normalize_field(field)

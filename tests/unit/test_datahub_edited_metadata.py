from __future__ import annotations

import pytest

from toxicjoin.context.datahub import DataHubMetadataError, _normalize_field
from toxicjoin.models import SensitivityCategory


def test_mcp_cleaned_edited_tags_drive_classification() -> None:
    field = {
        "fieldPath": "patient_nbr",
        "editedTags": ["toxicjoin:stable-pseudonym"],
    }

    normalized = _normalize_field(field)

    assert normalized.category == SensitivityCategory.STABLE_PSEUDONYM
    assert normalized.tags == ("toxicjoin:stable-pseudonym",)


def test_mcp_cleaned_edited_glossary_terms_drive_classification() -> None:
    field = {
        "fieldPath": "readmitted",
        "editedGlossaryTerms": ["SensitiveAttribute"],
    }

    normalized = _normalize_field(field)

    assert normalized.category == SensitivityCategory.SENSITIVE_ATTRIBUTE
    assert normalized.glossary_terms == ("SensitiveAttribute",)


def test_system_and_edited_metadata_are_merged() -> None:
    field = {
        "fieldPath": "patient_nbr",
        "tags": ["toxicjoin:stable-pseudonym"],
        "editedTags": ["stable-pseudonym"],
    }

    normalized = _normalize_field(field)

    assert normalized.category == SensitivityCategory.STABLE_PSEUDONYM
    assert normalized.tags == (
        "stable-pseudonym",
        "toxicjoin:stable-pseudonym",
    )


def test_conflicting_system_and_edited_categories_fail_closed() -> None:
    field = {
        "fieldPath": "patient_nbr",
        "tags": ["toxicjoin:stable-pseudonym"],
        "editedTags": ["toxicjoin:quasi-identifier"],
    }

    with pytest.raises(DataHubMetadataError, match="conflicting sensitivity"):
        _normalize_field(field)


def test_nested_graphql_and_cleaned_mcp_forms_can_coexist() -> None:
    field = {
        "fieldPath": "readmitted",
        "tags": {
            "tags": [
                {
                    "tag": {
                        "properties": {
                            "name": "toxicjoin:sensitive-attribute"
                        }
                    }
                }
            ]
        },
        "editedGlossaryTerms": ["SensitiveAttribute"],
    }

    normalized = _normalize_field(field)

    assert normalized.category == SensitivityCategory.SENSITIVE_ATTRIBUTE
    assert normalized.tags == ("toxicjoin:sensitive-attribute",)
    assert normalized.glossary_terms == ("SensitiveAttribute",)

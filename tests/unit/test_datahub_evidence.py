from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import SecretStr, ValidationError

from toxicjoin.context.datahub import DataHubSnapshot
from toxicjoin.context.fixture import FixtureCatalog, FixtureDataset, FixtureField
from toxicjoin.evidence.datahub import (
    DataHubEvidenceBundle,
    DataHubEvidenceError,
    build_datahub_evidence_bundle,
    datahub_source_identity,
)
from toxicjoin.evidence.models import EvidenceSource
from toxicjoin.integrations.datahub_mcp import DataHubMcpSettings
from toxicjoin.models import ColumnRef, LineageSource, SensitivityCategory


OBSERVED_AT = datetime(2026, 7, 25, 8, 30, tzinfo=timezone.utc)
SOURCE_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.source,PROD)"
DERIVED_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.derived,PROD)"
UNKNOWN_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,external.unknown,PROD)"


def _settings(*, gms_url: str = "https://DATAHUB.EXAMPLE:443/") -> DataHubMcpSettings:
    return DataHubMcpSettings(
        gms_url=gms_url,
        gms_token=SecretStr("do-not-leak-this-token"),
        command="uvx",
        args=("mcp-server-datahub",),
    )


def _snapshot(*, reverse_datasets: bool = False) -> DataHubSnapshot:
    source = FixtureDataset(
        urn=SOURCE_URN,
        owner="urn:li:corpuser:data-owner",
        domain="urn:li:domain:customer-security",
        fields={
            "customer_id": FixtureField(
                category=SensitivityCategory.STABLE_PSEUDONYM,
                tags=("toxicjoin:stable-pseudonym",),
            ),
            "secret": FixtureField(
                category=SensitivityCategory.SENSITIVE_ATTRIBUTE,
                glossary_terms=("Sensitive Attribute",),
            ),
        },
    )
    derived = FixtureDataset(
        urn=DERIVED_URN,
        fields={
            "harmless_value": FixtureField(
                category=SensitivityCategory.PUBLIC_OR_LOW_RISK,
                tags=("toxicjoin:public-or-low-risk",),
                lineage_sources=(
                    LineageSource(
                        ref=ColumnRef(dataset="source", field_path="customer_id"),
                        category=SensitivityCategory.STABLE_PSEUDONYM,
                        datahub_urn=SOURCE_URN,
                    ),
                ),
            ),
            "unknown_value": FixtureField(
                category=SensitivityCategory.UNCLASSIFIED,
                lineage_sources=(
                    LineageSource(
                        ref=ColumnRef(
                            dataset=f"@datahub:{UNKNOWN_URN}",
                            field_path="customer_id",
                        ),
                        category=SensitivityCategory.UNCLASSIFIED,
                        datahub_urn=UNKNOWN_URN,
                    ),
                ),
            ),
        },
    )
    datasets = (
        {"derived": derived, "source": source}
        if reverse_datasets
        else {"source": source, "derived": derived}
    )
    return DataHubSnapshot(
        catalog=FixtureCatalog(version="datahub-mcp:evidence-test-v1", datasets=datasets),
        verified_entities=tuple(sorted((SOURCE_URN, DERIVED_URN))),
        field_counts={"source": 2, "derived": 2},
        lineage_sample={"relationships": [{"entity": {"urn": SOURCE_URN}}]},
        discovered_tools=("get_entities", "get_lineage", "list_schema_fields"),
        observed_at=OBSERVED_AT,
    )


def _find_claim(bundle: DataHubEvidenceBundle, *, subject: str, predicate: str):
    matches = [
        claim
        for claim in bundle.claims
        if claim.subject == subject and claim.predicate == predicate
    ]
    assert len(matches) == 1
    return matches[0]


def test_source_identity_is_redacted_and_canonical() -> None:
    identity = datahub_source_identity(_settings())
    normalized = datahub_source_identity(
        _settings(gms_url="https://datahub.example")
    )

    assert identity == normalized
    assert identity.startswith("datahub-mcp:gms_sha256=")
    assert "datahub.example" not in identity
    assert ":443" not in identity
    assert "do-not-leak-this-token" not in identity
    assert "launcher_sha256=" in identity


def test_bundle_binds_every_claim_to_exact_snapshot_root() -> None:
    snapshot = _snapshot()
    bundle = build_datahub_evidence_bundle(snapshot, _settings())

    assert bundle.snapshot_sha256 == snapshot.snapshot_sha256
    assert bundle.catalog_version == snapshot.catalog.version
    assert bundle.expires_at.timestamp() - bundle.observed_at.timestamp() == 300
    roots = [
        claim
        for claim in bundle.claims
        if claim.predicate == "datahub.snapshot_sha256"
    ]
    assert len(roots) == 1
    root = roots[0]
    assert root.value == snapshot.snapshot_sha256
    assert root.supporting_claim_ids == ()
    assert all(claim.source == EvidenceSource.DATAHUB_MCP for claim in bundle.claims)
    assert all(
        claim.supporting_claim_ids == (root.claim_id,)
        for claim in bundle.claims
        if claim.claim_id != root.claim_id
    )


def test_category_and_lineage_governance_are_issued_fail_closed() -> None:
    bundle = build_datahub_evidence_bundle(_snapshot(), _settings())

    harmless_subject = f"{DERIVED_URN}#harmless_value"
    harmless_category = _find_claim(
        bundle,
        subject=harmless_subject,
        predicate="toxicjoin.sensitivity_category",
    )
    harmless_lineage = _find_claim(
        bundle,
        subject=harmless_subject,
        predicate="toxicjoin.lineage_governance_complete",
    )
    assert harmless_category.value == SensitivityCategory.PUBLIC_OR_LOW_RISK.value
    assert harmless_category.complete is True
    assert harmless_lineage.value == "true"

    unknown_subject = f"{DERIVED_URN}#unknown_value"
    unknown_category = _find_claim(
        bundle,
        subject=unknown_subject,
        predicate="toxicjoin.sensitivity_category",
    )
    unknown_lineage = _find_claim(
        bundle,
        subject=unknown_subject,
        predicate="toxicjoin.lineage_governance_complete",
    )
    assert unknown_category.value == SensitivityCategory.UNCLASSIFIED.value
    assert unknown_category.complete is False
    assert unknown_lineage.value == "false"

    edge_category_claims = [
        claim
        for claim in bundle.claims
        if claim.subject.startswith(f"{unknown_subject}::lineage::")
        and claim.predicate == "toxicjoin.lineage_source_category"
    ]
    assert len(edge_category_claims) == 1
    assert edge_category_claims[0].value == SensitivityCategory.UNCLASSIFIED.value
    assert edge_category_claims[0].complete is False


def test_owner_domain_tags_and_glossary_are_preserved_without_secret_leakage() -> None:
    bundle = build_datahub_evidence_bundle(_snapshot(), _settings())

    owner = _find_claim(bundle, subject=SOURCE_URN, predicate="datahub.owner")
    domain = _find_claim(bundle, subject=SOURCE_URN, predicate="datahub.domain")
    tags = _find_claim(
        bundle,
        subject=f"{SOURCE_URN}#customer_id",
        predicate="datahub.tags",
    )
    glossary = _find_claim(
        bundle,
        subject=f"{SOURCE_URN}#secret",
        predicate="datahub.glossary_terms",
    )

    assert owner.value == "urn:li:corpuser:data-owner"
    assert domain.value == "urn:li:domain:customer-security"
    assert tags.value == '["toxicjoin:stable-pseudonym"]'
    assert glossary.value == '["Sensitive Attribute"]'
    assert all(
        "do-not-leak-this-token" not in claim.model_dump_json()
        for claim in bundle.claims
    )
    assert all("datahub.example" not in claim.model_dump_json() for claim in bundle.claims)


def test_bundle_is_deterministic_across_dataset_insertion_order() -> None:
    forward = build_datahub_evidence_bundle(_snapshot(), _settings())
    reverse = build_datahub_evidence_bundle(
        _snapshot(reverse_datasets=True),
        _settings(),
    )

    assert forward.evidence_root_sha256 == reverse.evidence_root_sha256
    assert forward.claims == reverse.claims


def test_bundle_root_tampering_is_rejected() -> None:
    bundle = build_datahub_evidence_bundle(_snapshot(), _settings())
    payload = bundle.model_dump(mode="json")
    payload["evidence_root_sha256"] = "0" * 64

    with pytest.raises(ValidationError, match="root hash mismatch"):
        DataHubEvidenceBundle.model_validate(payload)


def test_source_identity_rejects_credential_or_ambiguous_urls() -> None:
    with pytest.raises(DataHubEvidenceError, match="userinfo"):
        datahub_source_identity(_settings(gms_url="https://user:pass@datahub.example"))
    with pytest.raises(DataHubEvidenceError, match="query or fragment"):
        datahub_source_identity(_settings(gms_url="https://datahub.example/?tenant=a"))
    with pytest.raises(DataHubEvidenceError, match="query or fragment"):
        datahub_source_identity(_settings(gms_url="https://datahub.example/#fragment"))


def test_evidence_ttl_is_bounded() -> None:
    snapshot = _snapshot()

    with pytest.raises(ValueError, match="max age"):
        build_datahub_evidence_bundle(snapshot, _settings(), max_age_seconds=0)
    with pytest.raises(ValueError, match="max age"):
        build_datahub_evidence_bundle(snapshot, _settings(), max_age_seconds=3601)


def test_bundle_claims_are_bound_to_configured_launcher_identity() -> None:
    default_bundle = build_datahub_evidence_bundle(_snapshot(), _settings())
    alternate = _settings().model_copy(
        update={"args": ("mcp-server-datahub", "--different")}
    )
    alternate_bundle = build_datahub_evidence_bundle(_snapshot(), alternate)

    assert default_bundle.source_identity != alternate_bundle.source_identity
    assert default_bundle.evidence_root_sha256 != alternate_bundle.evidence_root_sha256

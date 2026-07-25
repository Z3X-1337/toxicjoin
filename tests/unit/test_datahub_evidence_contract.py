from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import SecretStr, ValidationError

from toxicjoin.context.datahub import DataHubSnapshot
from toxicjoin.context.fixture import FixtureCatalog, FixtureDataset, FixtureField
from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.evidence.datahub import (
    DataHubEvidenceBundle,
    build_datahub_evidence_bundle,
)
from toxicjoin.evidence.models import (
    DerivationKind,
    EvidenceSource,
    build_evidence_claim,
)
from toxicjoin.integrations.datahub_mcp import DataHubMcpSettings
from toxicjoin.models import SensitivityCategory


NOW = datetime(2026, 7, 25, 9, 0, tzinfo=timezone.utc)
DATASET_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.contract,PROD)"


def _bundle() -> DataHubEvidenceBundle:
    snapshot = DataHubSnapshot(
        catalog=FixtureCatalog(
            version="datahub-mcp:contract-test-v1",
            datasets={
                "contract": FixtureDataset(
                    urn=DATASET_URN,
                    fields={
                        "secret": FixtureField(
                            category=SensitivityCategory.SENSITIVE_ATTRIBUTE,
                            tags=("toxicjoin:sensitive-attribute",),
                        )
                    },
                )
            },
        ),
        verified_entities=(DATASET_URN,),
        field_counts={"contract": 1},
        lineage_sample={"relationships": [{"entity": {"urn": DATASET_URN}}]},
        discovered_tools=("get_entities", "get_lineage", "list_schema_fields"),
        observed_at=NOW,
    )
    settings = DataHubMcpSettings(
        gms_url="https://datahub.example",
        gms_token=SecretStr("not-serialized"),
        command="uvx",
        args=("mcp-server-datahub",),
    )
    return build_datahub_evidence_bundle(snapshot, settings)


def _json_datetime(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _rebuild_payload_with_claim(
    bundle: DataHubEvidenceBundle,
    *,
    replacement_index: int,
    replacement_claim,
) -> dict[str, object]:
    claims = list(bundle.claims)
    claims[replacement_index] = replacement_claim
    claims = sorted(claims, key=lambda claim: claim.claim_id)
    evidence_root = canonical_json_sha256(
        {
            "schema_version": bundle.schema_version,
            "source_identity": bundle.source_identity,
            "snapshot_sha256": bundle.snapshot_sha256,
            "catalog_version": bundle.catalog_version,
            "observed_at": _json_datetime(bundle.observed_at),
            "expires_at": _json_datetime(bundle.expires_at),
            "claim_sha256s": [claim.content_sha256 for claim in claims],
        }
    )
    return {
        "schema_version": bundle.schema_version,
        "source_identity": bundle.source_identity,
        "snapshot_sha256": bundle.snapshot_sha256,
        "catalog_version": bundle.catalog_version,
        "observed_at": _json_datetime(bundle.observed_at),
        "expires_at": _json_datetime(bundle.expires_at),
        "claims": [claim.model_dump(mode="json") for claim in claims],
        "evidence_root_sha256": evidence_root,
    }


def test_mapped_security_predicate_cannot_be_spoofed_as_runtime_observed() -> None:
    bundle = _bundle()
    target_index, original = next(
        (index, claim)
        for index, claim in enumerate(bundle.claims)
        if claim.predicate == "toxicjoin.sensitivity_category"
    )
    assert original.derivation == DerivationKind.EXPLICIT_MAPPING

    spoofed = build_evidence_claim(
        subject=original.subject,
        predicate=original.predicate,
        value=original.value,
        source=EvidenceSource.DATAHUB_MCP,
        derivation=DerivationKind.RUNTIME_OBSERVED,
        source_identity=original.source_identity,
        observed_at=original.observed_at,
        expires_at=original.expires_at,
        complete=original.complete,
        supporting_claim_ids=original.supporting_claim_ids,
    )
    payload = _rebuild_payload_with_claim(
        bundle,
        replacement_index=target_index,
        replacement_claim=spoofed,
    )

    with pytest.raises(ValidationError, match="predicate derivation mismatch"):
        DataHubEvidenceBundle.model_validate(payload)


def test_unknown_predicate_is_rejected_even_with_valid_hashes() -> None:
    bundle = _bundle()
    target_index, original = next(
        (index, claim)
        for index, claim in enumerate(bundle.claims)
        if claim.predicate == "datahub.tags"
    )

    unknown = build_evidence_claim(
        subject=original.subject,
        predicate="datahub.unrecognized_security_fact",
        value=original.value,
        source=EvidenceSource.DATAHUB_MCP,
        derivation=DerivationKind.RUNTIME_OBSERVED,
        source_identity=original.source_identity,
        observed_at=original.observed_at,
        expires_at=original.expires_at,
        complete=original.complete,
        supporting_claim_ids=original.supporting_claim_ids,
    )
    payload = _rebuild_payload_with_claim(
        bundle,
        replacement_index=target_index,
        replacement_claim=unknown,
    )

    with pytest.raises(ValidationError, match="unsupported DataHub evidence predicate"):
        DataHubEvidenceBundle.model_validate(payload)

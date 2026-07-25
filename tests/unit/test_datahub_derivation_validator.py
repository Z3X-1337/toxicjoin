from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import SecretStr, ValidationError

from toxicjoin.context.datahub import DataHubSnapshot
from toxicjoin.context.fixture import FixtureCatalog, FixtureDataset, FixtureField
from toxicjoin.evidence.datahub import (
    DataHubEvidenceBundle,
    build_datahub_evidence_bundle,
    compute_datahub_evidence_root,
)
from toxicjoin.evidence.derivation import (
    DataHubDerivationValidation,
    DataHubDerivationValidationError,
    validate_datahub_evidence_derivations,
)
from toxicjoin.evidence.models import (
    DerivationKind,
    EvidenceTrustState,
    build_evidence_claim,
)
from toxicjoin.evidence.policy import default_evidence_policy
from toxicjoin.evidence.resolver import resolve_evidence
from toxicjoin.integrations.datahub_mcp import DataHubMcpSettings
from toxicjoin.models import ColumnRef, LineageSource, SensitivityCategory


OBSERVED_AT = datetime(2026, 7, 25, 10, 0, tzinfo=timezone.utc)
SOURCE_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.validator_source,PROD)"
DERIVED_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.validator_derived,PROD)"


def _settings(*, host: str = "datahub.example") -> DataHubMcpSettings:
    return DataHubMcpSettings(
        gms_url=f"https://{host}",
        gms_token=SecretStr("validator-secret-token"),
        command="uvx",
        args=("mcp-server-datahub",),
    )


def _snapshot(*, sensitive_tag: str = "toxicjoin:sensitive-attribute") -> DataHubSnapshot:
    source = FixtureDataset(
        urn=SOURCE_URN,
        owner="urn:li:corpuser:validator-owner",
        domain="urn:li:domain:validator-domain",
        fields={
            "customer_id": FixtureField(
                category=SensitivityCategory.STABLE_PSEUDONYM,
                tags=("toxicjoin:stable-pseudonym",),
            ),
            "secret": FixtureField(
                category=SensitivityCategory.SENSITIVE_ATTRIBUTE,
                tags=(sensitive_tag,),
                glossary_terms=("Sensitive Attribute",),
            ),
        },
    )
    derived = FixtureDataset(
        urn=DERIVED_URN,
        fields={
            "secret_copy": FixtureField(
                category=SensitivityCategory.SENSITIVE_ATTRIBUTE,
                tags=("toxicjoin:sensitive-attribute",),
                lineage_sources=(
                    LineageSource(
                        ref=ColumnRef(dataset="source", field_path="secret"),
                        category=SensitivityCategory.SENSITIVE_ATTRIBUTE,
                        datahub_urn=SOURCE_URN,
                    ),
                ),
            )
        },
    )
    return DataHubSnapshot(
        catalog=FixtureCatalog(
            version="datahub-mcp:validator-v1",
            datasets={"source": source, "derived": derived},
        ),
        verified_entities=tuple(sorted((SOURCE_URN, DERIVED_URN))),
        field_counts={"source": 2, "derived": 1},
        lineage_sample={"relationships": [{"entity": {"urn": SOURCE_URN}}]},
        discovered_tools=("get_entities", "get_lineage", "list_schema_fields"),
        observed_at=OBSERVED_AT,
    )


def _bundle() -> DataHubEvidenceBundle:
    return build_datahub_evidence_bundle(_snapshot(), _settings())


def _find_claim(bundle: DataHubEvidenceBundle, *, predicate: str, subject: str | None = None):
    matches = [
        claim
        for claim in bundle.claims
        if claim.predicate == predicate and (subject is None or claim.subject == subject)
    ]
    assert len(matches) == 1
    return matches[0]


def _rebuild_bundle(
    original: DataHubEvidenceBundle,
    claims,
) -> DataHubEvidenceBundle:
    ordered = tuple(sorted(claims, key=lambda claim: claim.claim_id))
    unchecked = DataHubEvidenceBundle.model_construct(
        schema_version=original.schema_version,
        source_identity=original.source_identity,
        snapshot_sha256=original.snapshot_sha256,
        catalog_version=original.catalog_version,
        observed_at=original.observed_at,
        expires_at=original.expires_at,
        claims=ordered,
        evidence_root_sha256="0" * 64,
    )
    evidence_root = compute_datahub_evidence_root(unchecked)
    return DataHubEvidenceBundle(
        source_identity=original.source_identity,
        snapshot_sha256=original.snapshot_sha256,
        catalog_version=original.catalog_version,
        observed_at=original.observed_at,
        expires_at=original.expires_at,
        claims=ordered,
        evidence_root_sha256=evidence_root,
    )


def test_validator_replays_bundle_and_commits_exact_claim_partition() -> None:
    bundle = _bundle()
    now = OBSERVED_AT + timedelta(seconds=30)

    validation = validate_datahub_evidence_derivations(
        bundle,
        _snapshot(),
        _settings(),
        now=now,
    )

    assert validation.evidence_root_sha256 == bundle.evidence_root_sha256
    assert validation.snapshot_sha256 == bundle.snapshot_sha256
    assert validation.source_identity == bundle.source_identity
    assert validation.evidence_observed_at == bundle.observed_at
    assert validation.evidence_expires_at == bundle.expires_at
    assert validation.freshness_policy_seconds == 300
    assert validation.validated_at == now
    assert set(validation.observed_claim_ids).isdisjoint(validation.mapped_claim_ids)
    assert set(validation.observed_claim_ids) | set(validation.mapped_claim_ids) == {
        claim.claim_id for claim in bundle.claims
    }
    assert validation.mapped_claim_ids


def test_validator_is_deterministic_for_same_bundle_snapshot_settings_and_time() -> None:
    bundle = _bundle()
    now = OBSERVED_AT + timedelta(seconds=45)

    first = validate_datahub_evidence_derivations(
        bundle,
        _snapshot(),
        _settings(),
        now=now,
    )
    second = validate_datahub_evidence_derivations(
        bundle,
        _snapshot(),
        _settings(),
        now=now,
    )

    assert first == second
    assert first.validation_sha256 == second.validation_sha256


def test_validator_rejects_mapped_value_tampering_with_recomputed_hashes() -> None:
    bundle = _bundle()
    target_subject = f"{SOURCE_URN}#secret"
    original = _find_claim(
        bundle,
        subject=target_subject,
        predicate="toxicjoin.sensitivity_category",
    )
    assert original.derivation == DerivationKind.EXPLICIT_MAPPING

    tampered = build_evidence_claim(
        subject=original.subject,
        predicate=original.predicate,
        value=SensitivityCategory.PUBLIC_OR_LOW_RISK.value,
        source=original.source,
        derivation=original.derivation,
        source_identity=original.source_identity,
        observed_at=original.observed_at,
        expires_at=original.expires_at,
        complete=original.complete,
        supporting_claim_ids=original.supporting_claim_ids,
    )
    claims = [tampered if claim.claim_id == original.claim_id else claim for claim in bundle.claims]
    attacker_bundle = _rebuild_bundle(bundle, claims)

    with pytest.raises(DataHubDerivationValidationError, match="content does not match"):
        validate_datahub_evidence_derivations(
            attacker_bundle,
            _snapshot(),
            _settings(),
            now=OBSERVED_AT + timedelta(seconds=30),
        )


def test_validator_rejects_dependency_tampering_with_recomputed_hashes() -> None:
    bundle = _bundle()
    target_subject = f"{SOURCE_URN}#secret"
    original = _find_claim(
        bundle,
        subject=target_subject,
        predicate="toxicjoin.sensitivity_category",
    )
    root = _find_claim(bundle, predicate="datahub.snapshot_sha256")
    assert len(original.supporting_claim_ids) > 1

    weakened = build_evidence_claim(
        subject=original.subject,
        predicate=original.predicate,
        value=original.value,
        source=original.source,
        derivation=original.derivation,
        source_identity=original.source_identity,
        observed_at=original.observed_at,
        expires_at=original.expires_at,
        complete=original.complete,
        supporting_claim_ids=(root.claim_id,),
    )
    claims = [weakened if claim.claim_id == original.claim_id else claim for claim in bundle.claims]
    attacker_bundle = _rebuild_bundle(bundle, claims)

    with pytest.raises(DataHubDerivationValidationError, match="content does not match"):
        validate_datahub_evidence_derivations(
            attacker_bundle,
            _snapshot(),
            _settings(),
            now=OBSERVED_AT + timedelta(seconds=30),
        )


def test_validator_rejects_duplicate_semantic_claim_even_with_valid_root() -> None:
    bundle = _bundle()
    subject = f"{SOURCE_URN}#secret"
    original = _find_claim(bundle, subject=subject, predicate="datahub.tags")
    root = _find_claim(bundle, predicate="datahub.snapshot_sha256")

    duplicate = build_evidence_claim(
        subject=original.subject,
        predicate=original.predicate,
        value='["attacker-controlled-tag"]',
        source=original.source,
        derivation=original.derivation,
        source_identity=original.source_identity,
        observed_at=original.observed_at,
        expires_at=original.expires_at,
        supporting_claim_ids=(root.claim_id,),
    )
    attacker_bundle = _rebuild_bundle(bundle, (*bundle.claims, duplicate))

    with pytest.raises(DataHubDerivationValidationError, match="duplicate semantic claim"):
        validate_datahub_evidence_derivations(
            attacker_bundle,
            _snapshot(),
            _settings(),
            now=OBSERVED_AT + timedelta(seconds=30),
        )


def test_validator_rejects_snapshot_and_source_configuration_mismatch() -> None:
    bundle = _bundle()
    now = OBSERVED_AT + timedelta(seconds=30)

    with pytest.raises(DataHubDerivationValidationError, match="snapshot commitment"):
        validate_datahub_evidence_derivations(
            bundle,
            _snapshot(sensitive_tag="different-tag"),
            _settings(),
            now=now,
        )

    with pytest.raises(DataHubDerivationValidationError, match="source identity"):
        validate_datahub_evidence_derivations(
            bundle,
            _snapshot(),
            _settings(host="other-datahub.example"),
            now=now,
        )


def test_validator_rejects_candidate_controlled_freshness_extension() -> None:
    extended = build_datahub_evidence_bundle(
        _snapshot(),
        _settings(),
        max_age_seconds=600,
    )
    now = OBSERVED_AT + timedelta(seconds=30)

    with pytest.raises(DataHubDerivationValidationError, match="freshness window"):
        validate_datahub_evidence_derivations(
            extended,
            _snapshot(),
            _settings(),
            now=now,
        )

    trusted_extended = validate_datahub_evidence_derivations(
        extended,
        _snapshot(),
        _settings(),
        max_age_seconds=600,
        now=now,
    )
    assert trusted_extended.freshness_policy_seconds == 600
    assert trusted_extended.evidence_expires_at == extended.expires_at


def test_validator_fails_closed_for_future_stale_or_naive_validation_time() -> None:
    bundle = _bundle()

    with pytest.raises(DataHubDerivationValidationError, match="observed in the future"):
        validate_datahub_evidence_derivations(
            bundle,
            _snapshot(),
            _settings(),
            now=OBSERVED_AT - timedelta(seconds=1),
        )

    with pytest.raises(DataHubDerivationValidationError, match="stale"):
        validate_datahub_evidence_derivations(
            bundle,
            _snapshot(),
            _settings(),
            now=bundle.expires_at,
        )

    with pytest.raises(DataHubDerivationValidationError, match="timezone-aware"):
        validate_datahub_evidence_derivations(
            bundle,
            _snapshot(),
            _settings(),
            now=datetime(2026, 7, 25, 10, 0),
        )


def test_validation_does_not_make_mapped_claim_authoritative() -> None:
    bundle = _bundle()
    validate_datahub_evidence_derivations(
        bundle,
        _snapshot(),
        _settings(),
        now=OBSERVED_AT + timedelta(seconds=30),
    )
    subject = f"{SOURCE_URN}#secret"
    mapped = _find_claim(
        bundle,
        subject=subject,
        predicate="toxicjoin.sensitivity_category",
    )

    resolution = resolve_evidence(
        subject=subject,
        predicate=mapped.predicate,
        claims=(mapped,),
        policy=default_evidence_policy(),
        now=OBSERVED_AT + timedelta(seconds=30),
    )

    assert resolution.state == EvidenceTrustState.UNKNOWN
    assert resolution.value is None


def test_validation_commitment_tampering_is_rejected() -> None:
    validation = validate_datahub_evidence_derivations(
        _bundle(),
        _snapshot(),
        _settings(),
        now=OBSERVED_AT + timedelta(seconds=30),
    )
    payload = validation.model_dump(mode="json")
    payload["validation_sha256"] = "0" * 64

    with pytest.raises(ValidationError, match="validation hash mismatch"):
        DataHubDerivationValidation.model_validate(payload)

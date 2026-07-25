from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from toxicjoin.api import create_app
from toxicjoin.api.models import DEFAULT_SUBJECT_KEY
from toxicjoin.api.scenarios import ALLOW_PUBLIC_AGGREGATE_SQL, FLAGSHIP_REWRITE_SQL
from toxicjoin.auth import (
    ApiKeyAuthenticator,
    ApiKeyCredentialConfig,
    AuthScope,
    RequestIdentity,
    bind_request_identity,
)
from toxicjoin.context import DataHubSnapshot, DataHubSnapshotContextResolver
from toxicjoin.context.governance import GovernanceContextBinding
from toxicjoin.context.models import ContextResolution
from toxicjoin.demo import default_fixture_catalog, seed_database
from toxicjoin.disclosure import DisclosureLedger
from toxicjoin.execute import (
    DuckDBExecutor,
    ExecutionAuthorizationError,
    ExecutionAuthorizer,
)
from toxicjoin.models import Decision, PolicyDecision, ReasonCode
from toxicjoin.pipeline import PipelineRequest, ToxicJoinPipeline
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.receipts import ReceiptMode, ReceiptStore, build_receipt, compute_content_hash


SYSTEM_KEY = "p3b-system-read-key-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def _snapshot(
    *,
    observed_at: datetime,
    marker: str = "A",
) -> DataHubSnapshot:
    catalog = default_fixture_catalog()
    return DataHubSnapshot(
        catalog=catalog,
        verified_entities=tuple(dataset.urn for dataset in catalog.datasets.values()),
        field_counts={name: len(dataset.fields) for name, dataset in catalog.datasets.items()},
        lineage_sample={
            "relationships": [
                {
                    "direction": "UPSTREAM",
                    "freshness_test_marker": marker,
                }
            ]
        },
        discovered_tools=("get_entities", "get_lineage", "list_schema_fields"),
        observed_at=observed_at,
    )


def _identity() -> RequestIdentity:
    return RequestIdentity(
        principal_id="p3b-security-test",
        credential_id="p3b-security-test-key",
        agent_id="p3b-security-agent",
        session_id="p3b-session",
    )


def _binding(
    snapshot: DataHubSnapshot,
    *,
    max_age_seconds: float = 300.0,
) -> GovernanceContextBinding:
    return GovernanceContextBinding(
        source="datahub-mcp",
        snapshot_sha256=snapshot.snapshot_sha256,
        catalog_version=snapshot.catalog.version,
        observed_at=snapshot.observed_at,
        expires_at=snapshot.observed_at + timedelta(seconds=max_age_seconds),
    )


def _allow_decision() -> PolicyDecision:
    return PolicyDecision(
        decision=Decision.ALLOW,
        reason_codes=(ReasonCode.NO_COMPOSITIONAL_RISK,),
        policy_version=load_policy().version,
        evidence={"test": "p3b-governance-provenance"},
    )


def test_same_governance_content_with_fresh_observation_gets_new_valid_binding() -> None:
    first_observed = datetime(2026, 7, 25, 18, 0, tzinfo=timezone.utc)
    second_observed = first_observed + timedelta(seconds=30)
    first = _snapshot(observed_at=first_observed)
    second = first.model_copy(update={"observed_at": second_observed})

    assert first.snapshot_sha256 == second.snapshot_sha256

    first_resolver = DataHubSnapshotContextResolver(
        first,
        clock=lambda: first_observed + timedelta(seconds=1),
    )
    second_resolver = DataHubSnapshotContextResolver(
        second,
        clock=lambda: second_observed + timedelta(seconds=1),
    )
    first_binding = first_resolver.current_governance_binding()
    second_binding = second_resolver.current_governance_binding()

    assert first_binding.snapshot_sha256 == second_binding.snapshot_sha256
    assert first_binding.observed_at != second_binding.observed_at
    assert first_binding.expires_at != second_binding.expires_at


def test_pipeline_blocks_mixed_snapshot_rewrite_context(tmp_path) -> None:
    observed = datetime(2026, 7, 25, 18, 0, tzinfo=timezone.utc)
    first = _snapshot(observed_at=observed, marker="A")
    second = _snapshot(observed_at=observed + timedelta(seconds=1), marker="B")

    class ReplacingResolver(DataHubSnapshotContextResolver):
        def __init__(self) -> None:
            super().__init__(first, clock=lambda: observed + timedelta(seconds=2))
            self.calls = 0

        def resolve_with_governance_binding(self, query_plan):
            resolution, binding = super().resolve_with_governance_binding(query_plan)
            self.calls += 1
            if self.calls == 1:
                self.replace_snapshot(second)
            return resolution, binding

    resolver = ReplacingResolver()
    pipeline = ToxicJoinPipeline(
        context_resolver=resolver,
        policy_engine=PolicyEngine(load_policy()),
        receipt_store=ReceiptStore(tmp_path / "receipts"),
        mode=ReceiptMode.LIVE,
        disclosure_ledger=DisclosureLedger(tmp_path / "disclosures.sqlite3"),
        stateful_privacy_required=True,
        include_sanitized_sql=False,
    )
    request = PipelineRequest(
        task_purpose="P3-B mixed snapshot rewrite test",
        sql=FLAGSHIP_REWRITE_SQL,
        subject_key=DEFAULT_SUBJECT_KEY,
    )

    with bind_request_identity(_identity()):
        result = pipeline.analyze(request)

    assert result.initial_decision.decision == Decision.REWRITE
    assert result.final_decision is not None
    assert result.final_decision.decision == Decision.BLOCK
    assert result.final_decision.reason_codes == (ReasonCode.DATAHUB_CONTEXT_DRIFT,)
    assert result.receipt.governance is not None
    assert result.receipt.governance.snapshot_sha256 == first.snapshot_sha256
    assert result.receipt.execution is None


def test_authorization_rejects_snapshot_replacement_after_issuance() -> None:
    observed = datetime(2026, 7, 25, 18, 0, tzinfo=timezone.utc)
    first = _snapshot(observed_at=observed, marker="A")
    second = _snapshot(observed_at=observed + timedelta(seconds=1), marker="B")
    resolver = DataHubSnapshotContextResolver(
        first,
        clock=lambda: observed + timedelta(seconds=2),
    )
    authorizer = ExecutionAuthorizer(
        context_resolver=resolver,
        policy_engine=PolicyEngine(load_policy()),
        secret_key=b"p3b-authorization-test-key-material" * 2,
    )
    binding = resolver.current_governance_binding()
    authorization = authorizer.issue(
        ALLOW_PUBLIC_AGGREGATE_SQL,
        task_purpose="Count orders by public category",
        subject_key=DEFAULT_SUBJECT_KEY,
        expected_governance_binding=binding,
    )

    resolver.replace_snapshot(second)

    with pytest.raises(ExecutionAuthorizationError) as raised:
        authorizer.verify_and_consume(
            authorization,
            ALLOW_PUBLIC_AGGREGATE_SQL,
            task_purpose="Count orders by public category",
            subject_key=DEFAULT_SUBJECT_KEY,
        )

    assert raised.value.code == "AUTH_CONTEXT_DRIFT"


def test_governance_binding_tampering_invalidates_authorization_mac() -> None:
    observed = datetime(2026, 7, 25, 18, 0, tzinfo=timezone.utc)
    snapshot = _snapshot(observed_at=observed)
    resolver = DataHubSnapshotContextResolver(
        snapshot,
        clock=lambda: observed + timedelta(seconds=1),
    )
    authorizer = ExecutionAuthorizer(
        context_resolver=resolver,
        policy_engine=PolicyEngine(load_policy()),
        secret_key=b"p3b-mac-tamper-test-key-material" * 2,
    )
    authorization = authorizer.issue(
        ALLOW_PUBLIC_AGGREGATE_SQL,
        task_purpose="Count orders by public category",
        subject_key=DEFAULT_SUBJECT_KEY,
        expected_governance_binding=resolver.current_governance_binding(),
    )
    assert authorization.governance_binding is not None
    tampered_binding = authorization.governance_binding.model_copy(
        update={"snapshot_sha256": "f" * 64}
    )
    tampered = authorization.model_copy(update={"governance_binding": tampered_binding})

    with pytest.raises(ExecutionAuthorizationError) as raised:
        authorizer.verify_and_consume(
            tampered,
            ALLOW_PUBLIC_AGGREGATE_SQL,
            task_purpose="Count orders by public category",
            subject_key=DEFAULT_SUBJECT_KEY,
        )

    assert raised.value.code == "AUTH_INVALID_MAC"


def test_live_receipt_without_governance_provenance_is_rejected() -> None:
    with pytest.raises(ValidationError, match="governance provenance"):
        build_receipt(
            task_purpose="P3-B live provenance requirement",
            mode=ReceiptMode.LIVE,
            original_sql="SELECT 1",
            initial_decision=_allow_decision(),
            context=ContextResolution(
                projected_context=(),
                all_referenced_context=(),
                failures=(),
            ),
            identity=_identity(),
            governance_binding=None,
            include_sanitized_sql=False,
        )


def test_receipt_governance_tampering_fails_integrity_check(tmp_path) -> None:
    observed = datetime(2026, 7, 25, 18, 0, tzinfo=timezone.utc)
    snapshot = _snapshot(observed_at=observed)
    receipt = build_receipt(
        task_purpose="P3-B receipt tamper test",
        mode=ReceiptMode.LIVE,
        original_sql="SELECT 1",
        initial_decision=_allow_decision(),
        context=ContextResolution(
            projected_context=(),
            all_referenced_context=(),
            failures=(),
        ),
        identity=_identity(),
        governance_binding=_binding(snapshot),
        include_sanitized_sql=False,
        receipt_id="tj_0123456789abcd01",
    )
    store = ReceiptStore(tmp_path / "receipts")
    receipt = store.seal(receipt)
    path = store.write(receipt)
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["governance"]["snapshot_sha256"] = "e" * 64
    raw["content_sha256"] = compute_content_hash(raw)
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(ValueError, match="integrity HMAC mismatch"):
        store.read(receipt.receipt_id)


def test_stale_datahub_degrades_readiness_but_not_liveness(tmp_path) -> None:
    observed = datetime(2026, 7, 25, 18, 0, tzinfo=timezone.utc)
    snapshot = _snapshot(observed_at=observed)
    resolver = DataHubSnapshotContextResolver(
        snapshot,
        max_age_seconds=300,
        clock=lambda: observed + timedelta(seconds=301),
    )
    database = tmp_path / "live.duckdb"
    seed_database(database)
    pipeline = ToxicJoinPipeline(
        context_resolver=resolver,
        policy_engine=PolicyEngine(load_policy()),
        receipt_store=ReceiptStore(tmp_path / "receipts"),
        mode=ReceiptMode.LIVE,
        executor=DuckDBExecutor(database),
        disclosure_ledger=DisclosureLedger(tmp_path / "disclosures.sqlite3"),
        stateful_privacy_required=True,
        include_sanitized_sql=False,
    )
    authenticator = ApiKeyAuthenticator(
        (
            ApiKeyCredentialConfig(
                credential_id="p3b-system",
                api_key=SYSTEM_KEY,
                principal_id="p3b-readiness-principal",
                scopes=(AuthScope.SYSTEM_READ,),
            ),
        )
    )
    app = create_app(pipeline, authenticator=authenticator)

    with TestClient(app) as client:
        liveness = client.get("/api/health")
        readiness = client.get(
            "/api/ready",
            headers={"Authorization": f"Bearer {SYSTEM_KEY}"},
        )

    assert liveness.status_code == 200
    assert liveness.json() == {"status": "ok"}
    assert readiness.status_code == 503
    assert readiness.json()["status"] == "degraded"
    assert readiness.json()["governance_ready"] is False


def test_stale_snapshot_provenance_is_preserved_in_block_receipt(tmp_path) -> None:
    observed = datetime(2026, 7, 25, 18, 0, tzinfo=timezone.utc)
    snapshot = _snapshot(observed_at=observed)
    resolver = DataHubSnapshotContextResolver(
        snapshot,
        max_age_seconds=300,
        clock=lambda: observed + timedelta(seconds=301),
    )
    pipeline = ToxicJoinPipeline(
        context_resolver=resolver,
        policy_engine=PolicyEngine(load_policy()),
        receipt_store=ReceiptStore(tmp_path / "receipts"),
        mode=ReceiptMode.LIVE,
        disclosure_ledger=DisclosureLedger(tmp_path / "disclosures.sqlite3"),
        stateful_privacy_required=True,
        include_sanitized_sql=False,
    )
    request = PipelineRequest(
        task_purpose="P3-B stale snapshot receipt provenance",
        sql=ALLOW_PUBLIC_AGGREGATE_SQL,
        subject_key=DEFAULT_SUBJECT_KEY,
    )

    with bind_request_identity(_identity()):
        result = pipeline.analyze(request)

    assert result.initial_decision.decision == Decision.BLOCK
    assert result.initial_decision.reason_codes == (ReasonCode.DATAHUB_CONTEXT_STALE,)
    assert result.receipt.governance is not None
    assert result.receipt.governance.snapshot_sha256 == snapshot.snapshot_sha256
    assert result.receipt.governance.expires_at == observed + timedelta(seconds=300)

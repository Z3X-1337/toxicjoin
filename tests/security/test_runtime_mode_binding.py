from __future__ import annotations

import pytest

from toxicjoin.api import create_default_pipeline
from toxicjoin.context import (
    ContextResolution,
    DataHubSnapshot,
    DataHubSnapshotContextResolver,
    FixtureContextResolver,
)
from toxicjoin.demo import default_fixture_catalog
from toxicjoin.pipeline import ToxicJoinPipeline
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.receipts import ReceiptMode, ReceiptStore


def _fixture_resolver() -> FixtureContextResolver:
    return FixtureContextResolver(default_fixture_catalog())


def _live_resolver() -> DataHubSnapshotContextResolver:
    catalog = default_fixture_catalog()
    snapshot = DataHubSnapshot(
        catalog=catalog,
        verified_entities=tuple(dataset.urn for dataset in catalog.datasets.values()),
        field_counts={
            name: len(dataset.fields) for name, dataset in catalog.datasets.items()
        },
        lineage_sample={"relationships": [{"direction": "UPSTREAM"}]},
        discovered_tools=("get_entities", "get_lineage", "list_schema_fields"),
    )
    return DataHubSnapshotContextResolver(snapshot)


def _pipeline(tmp_path, *, resolver, mode: ReceiptMode) -> ToxicJoinPipeline:
    return ToxicJoinPipeline(
        context_resolver=resolver,
        policy_engine=PolicyEngine(load_policy()),
        receipt_store=ReceiptStore(tmp_path / mode.value),
        mode=mode,
        executor=None,
    )


def test_default_pipeline_is_explicit_fixture_mode() -> None:
    pipeline = create_default_pipeline()

    assert pipeline.mode == ReceiptMode.FIXTURE
    assert isinstance(pipeline.context_resolver, FixtureContextResolver)
    assert not isinstance(pipeline.context_resolver, DataHubSnapshotContextResolver)


def test_live_mode_requires_verified_datahub_snapshot_resolver(tmp_path) -> None:
    with pytest.raises(
        ValueError,
        match="LIVE mode requires a verified DataHub snapshot context resolver",
    ):
        _pipeline(
            tmp_path,
            resolver=_fixture_resolver(),
            mode=ReceiptMode.LIVE,
        )


class UnknownResolver:
    def resolve(self, query_plan):
        return ContextResolution(
            projected_context=(),
            all_referenced_context=(),
            failures=(),
        )


def test_unknown_test_double_cannot_claim_live_mode(tmp_path) -> None:
    with pytest.raises(
        ValueError,
        match="LIVE mode requires a verified DataHub snapshot context resolver",
    ):
        _pipeline(
            tmp_path,
            resolver=UnknownResolver(),
            mode=ReceiptMode.LIVE,
        )


def test_fixture_and_replay_modes_reject_live_datahub_resolver(tmp_path) -> None:
    live = _live_resolver()

    with pytest.raises(ValueError, match="FIXTURE mode cannot use a live DataHub"):
        _pipeline(tmp_path, resolver=live, mode=ReceiptMode.FIXTURE)

    with pytest.raises(ValueError, match="REPLAY mode cannot use a live DataHub"):
        _pipeline(tmp_path, resolver=live, mode=ReceiptMode.REPLAY)


def test_live_mode_accepts_verified_datahub_snapshot_resolver(tmp_path) -> None:
    live = _live_resolver()
    pipeline = _pipeline(tmp_path, resolver=live, mode=ReceiptMode.LIVE)

    assert pipeline.mode == ReceiptMode.LIVE
    assert pipeline.context_resolver is live


def test_fixture_mode_keeps_custom_test_resolvers_available(tmp_path) -> None:
    resolver = UnknownResolver()
    pipeline = _pipeline(tmp_path, resolver=resolver, mode=ReceiptMode.FIXTURE)

    assert pipeline.mode == ReceiptMode.FIXTURE
    assert pipeline.context_resolver is resolver

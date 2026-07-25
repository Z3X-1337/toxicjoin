from __future__ import annotations

from datetime import datetime, timezone

import pytest

from toxicjoin.context.datahub import DataHubSnapshot, DataHubSnapshotContextResolver
from toxicjoin.context.fixture import FixtureCatalog, FixtureDataset, FixtureField
from toxicjoin.execute import ProofBoundExecutionAuthorizer
from toxicjoin.execute.proof_bound_authorization import (
    ProofBoundExecutionAuthorizer as ImplementationProofBoundExecutionAuthorizer,
)
from toxicjoin.models import SensitivityCategory
from toxicjoin.policy import PolicyEngine, load_policy

NOW = datetime(2027, 1, 15, tzinfo=timezone.utc)
URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.key_separation,PROD)"
SAME_KEY = b"same-proof-and-authorization-key-32bytes!!"


def _resolver() -> DataHubSnapshotContextResolver:
    snapshot = DataHubSnapshot(
        catalog=FixtureCatalog(
            version="datahub-mcp:key-separation-v1",
            datasets={
                "customers": FixtureDataset(
                    urn=URN,
                    fields={
                        "customer_id": FixtureField(
                            category=SensitivityCategory.STABLE_PSEUDONYM,
                        )
                    },
                )
            },
        ),
        verified_entities=(URN,),
        field_counts={"customers": 1},
        lineage_sample={"relationships": []},
        discovered_tools=("get_entities",),
        observed_at=NOW,
    )
    return DataHubSnapshotContextResolver(
        snapshot,
        max_age_seconds=300,
        clock=lambda: NOW,
    )


@pytest.mark.parametrize(
    "authorizer_type",
    (ProofBoundExecutionAuthorizer, ImplementationProofBoundExecutionAuthorizer),
)
def test_proof_and_authorization_hmac_keys_must_differ(authorizer_type) -> None:
    with pytest.raises(ValueError, match="must differ"):
        authorizer_type(
            context_resolver=_resolver(),
            policy_engine=PolicyEngine(load_policy()),
            privacy_proof_integrity_key=SAME_KEY,
            secret_key=SAME_KEY,
            clock=lambda: NOW.timestamp(),
        )

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
PROVENANCE_KEY = b"distinct-agent-provenance-key-32-bytes!!"
PROOF_KEY = b"distinct-proof-integrity-key-32-bytes!!"
AUTH_KEY = b"distinct-execution-auth-key-32-bytes!!"


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
    kwargs = {
        "context_resolver": _resolver(),
        "policy_engine": PolicyEngine(load_policy()),
        "privacy_proof_integrity_key": SAME_KEY,
        "secret_key": SAME_KEY,
        "clock": lambda: NOW.timestamp(),
    }
    if authorizer_type is ProofBoundExecutionAuthorizer:
        kwargs["agent_provenance_integrity_key"] = PROVENANCE_KEY

    with pytest.raises(ValueError, match="must differ"):
        authorizer_type(**kwargs)


def test_agent_provenance_key_must_differ_from_proof_key() -> None:
    with pytest.raises(ValueError, match="must differ"):
        ProofBoundExecutionAuthorizer(
            context_resolver=_resolver(),
            policy_engine=PolicyEngine(load_policy()),
            privacy_proof_integrity_key=SAME_KEY,
            agent_provenance_integrity_key=SAME_KEY,
            secret_key=AUTH_KEY,
            clock=lambda: NOW.timestamp(),
        )


def test_agent_provenance_key_must_differ_from_execution_key() -> None:
    with pytest.raises(ValueError, match="must differ"):
        ProofBoundExecutionAuthorizer(
            context_resolver=_resolver(),
            policy_engine=PolicyEngine(load_policy()),
            privacy_proof_integrity_key=PROOF_KEY,
            agent_provenance_integrity_key=SAME_KEY,
            secret_key=SAME_KEY,
            clock=lambda: NOW.timestamp(),
        )

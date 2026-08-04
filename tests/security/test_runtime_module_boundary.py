"""The runtime/experimental split must be verified, not asserted in prose.

About 40% of `src/` was staged vNext research that the HTTP runtime never invoked. Readers had
no way to tell which code was live except by tracing imports by hand, and nothing stopped a
future change from quietly promoting research into the product path — or from letting the
product silently depend on a module documented as experimental.

These tests pin the boundary in both directions.
"""

from __future__ import annotations

import importlib
import sys

import pytest


EXPERIMENTAL_PACKAGES = (
    "toxicjoin.prospective",
    "toxicjoin.repair",
)
"""Staged research. Real code with tests, but not invoked by any request path."""

RUNTIME_PACKAGES = (
    "toxicjoin.agent",
    "toxicjoin.api",
    "toxicjoin.context",
    "toxicjoin.disclosure",
    "toxicjoin.execute",
    "toxicjoin.pipeline",
    "toxicjoin.policy",
    "toxicjoin.receipts",
    "toxicjoin.rewrite",
    "toxicjoin.sql",
    "toxicjoin.verify",
)
"""Modules the executable product depends on."""


@pytest.fixture(scope="module")
def runtime_modules() -> frozenset[str]:
    for name in [name for name in sys.modules if name.startswith("toxicjoin")]:
        del sys.modules[name]
    importlib.import_module("toxicjoin.api.app")
    return frozenset(name for name in sys.modules if name.startswith("toxicjoin"))


def test_runtime_packages_are_actually_loaded(runtime_modules: frozenset[str]) -> None:
    for package in RUNTIME_PACKAGES:
        assert any(name.startswith(package) for name in runtime_modules), (
            f"{package} is declared as runtime but the API never imports it"
        )


def test_governed_agent_is_on_the_runtime_path(runtime_modules: frozenset[str]) -> None:
    """The agent boundary used to be unreachable from the API; it is now wired."""

    assert "toxicjoin.agent.runtime" in runtime_modules
    assert "toxicjoin.agent.governed" in runtime_modules


@pytest.mark.parametrize("package", EXPERIMENTAL_PACKAGES)
def test_experimental_packages_declare_their_status(package: str) -> None:
    module = importlib.import_module(package)
    doc = module.__doc__ or ""
    assert "EXPERIMENTAL" in doc, (
        f"{package} is not wired into the runtime and must say so in its module docstring"
    )


def test_experimental_code_never_decides_authorization() -> None:
    """Research modules must not be able to widen authority even if imported."""

    from toxicjoin.execute.authorization import ExecutionAuthorizer

    for package in EXPERIMENTAL_PACKAGES:
        module = importlib.import_module(package)
        for attribute in vars(module).values():
            if isinstance(attribute, type) and issubclass(attribute, ExecutionAuthorizer):
                pytest.fail(
                    f"{package} exports an ExecutionAuthorizer subclass; "
                    "authorization must stay in toxicjoin.execute"
                )


def test_proof_bound_execution_is_not_active_by_default() -> None:
    """`toxicjoin.proofs` is imported for typing only; the strict path stays unmigrated.

    If a future change makes the default authority proof-bound, this test fails and forces the
    claim boundary in the docs to be updated with it.
    """

    from toxicjoin.execute.authorization import ExecutionAuthorizer
    from toxicjoin.execute.proof_bound_authorization import ProofBoundExecutionAuthorizer
    from toxicjoin.context import FixtureContextResolver
    from toxicjoin.demo import default_fixture_catalog
    from toxicjoin.policy import PolicyEngine, load_policy

    authorizer = ExecutionAuthorizer(
        context_resolver=FixtureContextResolver(default_fixture_catalog()),
        policy_engine=PolicyEngine(load_policy()),
    )

    assert not isinstance(authorizer, ProofBoundExecutionAuthorizer)


def test_proofs_package_declares_its_partial_status() -> None:
    import toxicjoin.proofs

    assert "PARTIALLY WIRED" in (toxicjoin.proofs.__doc__ or "")

from __future__ import annotations

import hashlib

import pytest

from toxicjoin.auth import RequestIdentity
from toxicjoin.context.fixture import FixtureCatalog
from toxicjoin.demo import default_fixture_catalog
from toxicjoin.disclosure import (
    DisclosureSemanticError,
    build_disclosure_event,
    build_disclosure_scope,
    build_semantic_release,
    resolve_governed_subject_domain,
)
from toxicjoin.models import ColumnRef, SensitivityCategory
from toxicjoin.sql import analyze_sql


def _identity(
    *,
    principal: str = "principal-a",
    credential: str = "credential-a",
    agent: str | None = "agent-a",
    session: str | None = "session-a",
) -> RequestIdentity:
    return RequestIdentity(
        principal_id=principal,
        credential_id=credential,
        agent_id=agent,
        session_id=session,
    )


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def test_scope_ignores_credential_session_and_dataset_rotation_for_same_subject() -> None:
    catalog = default_fixture_catalog()
    customer_subject = resolve_governed_subject_domain(
        catalog,
        subject_key=ColumnRef(dataset="customers", field_path="customer_id"),
        source_datasets=("customers",),
    )
    order_subject = resolve_governed_subject_domain(
        catalog,
        subject_key=ColumnRef(dataset="orders", field_path="customer_id"),
        source_datasets=("orders",),
    )

    first = build_disclosure_scope(
        _identity(credential="credential-a", session="session-a"),
        customer_subject,
    )
    rotated = build_disclosure_scope(
        _identity(credential="credential-b", session="session-b"),
        order_subject,
    )

    assert customer_subject.dataset_urns != order_subject.dataset_urns
    assert customer_subject.namespace_sha256 == order_subject.namespace_sha256
    assert first.scope_sha256 == rotated.scope_sha256


def test_scope_changes_for_different_principal_agent_or_subject_namespace() -> None:
    catalog = default_fixture_catalog()
    customer_subject = resolve_governed_subject_domain(
        catalog,
        subject_key=ColumnRef(dataset="customers", field_path="customer_id"),
        source_datasets=("customers",),
    )
    base = build_disclosure_scope(_identity(), customer_subject)
    different_principal = build_disclosure_scope(
        _identity(principal="principal-b"), customer_subject
    )
    different_agent = build_disclosure_scope(
        _identity(agent="agent-b"), customer_subject
    )

    assert base.scope_sha256 != different_principal.scope_sha256
    assert base.scope_sha256 != different_agent.scope_sha256


def test_subject_key_must_be_governed_identifier_and_participate_in_query() -> None:
    catalog = default_fixture_catalog()

    with pytest.raises(DisclosureSemanticError, match="direct identifier or stable"):
        resolve_governed_subject_domain(
            catalog,
            subject_key=ColumnRef(dataset="orders", field_path="order_id"),
            source_datasets=("orders",),
        )

    with pytest.raises(DisclosureSemanticError, match="must participate"):
        resolve_governed_subject_domain(
            catalog,
            subject_key=ColumnRef(dataset="customers", field_path="customer_id"),
            source_datasets=("orders",),
        )


def test_conflicting_subject_categories_across_sources_fail_closed() -> None:
    catalog = FixtureCatalog.model_validate(
        {
            "version": "test",
            "datasets": {
                "a": {
                    "urn": "urn:li:dataset:a",
                    "fields": {
                        "person_id": {"category": "STABLE_PSEUDONYM"},
                    },
                },
                "b": {
                    "urn": "urn:li:dataset:b",
                    "fields": {
                        "person_id": {"category": "DIRECT_IDENTIFIER"},
                    },
                },
            },
        }
    )

    with pytest.raises(DisclosureSemanticError, match="conflicting governed"):
        resolve_governed_subject_domain(
            catalog,
            subject_key=ColumnRef(dataset="a", field_path="person_id"),
            source_datasets=("a", "b"),
        )


def test_semantic_hash_is_alias_insensitive_but_governance_sensitive() -> None:
    catalog = default_fixture_catalog()
    first = analyze_sql(
        "SELECT AVG(o.purchase_amount) AS amount_a FROM orders o",
        dialect="duckdb",
    )
    renamed = analyze_sql(
        "SELECT AVG(o.purchase_amount) AS amount_b FROM orders o",
        dialect="duckdb",
    )

    first_release = build_semantic_release(catalog, first)
    renamed_release = build_semantic_release(catalog, renamed)

    assert first_release.outputs[0].output_name != renamed_release.outputs[0].output_name
    assert first_release.semantic_sha256 == renamed_release.semantic_sha256
    assert first_release.outputs[0].sources[0].category == SensitivityCategory.SENSITIVE_ATTRIBUTE
    assert first_release.aggregate_functions == ("AVG",)


def test_semantic_release_captures_group_join_and_referenced_governance() -> None:
    catalog = default_fixture_catalog()
    plan = analyze_sql(
        """
        SELECT c.coarse_region, AVG(o.purchase_amount) AS avg_purchase
        FROM customers c
        JOIN orders o ON c.customer_id = o.customer_id
        GROUP BY c.coarse_region
        """,
        dialect="duckdb",
    )

    release = build_semantic_release(catalog, plan)

    assert len(release.source_dataset_urns) == 2
    assert {column.field_path for column in release.group_keys} == {"coarse_region"}
    assert {column.field_path for column in release.join_columns} == {"customer_id"}
    assert {column.field_path for column in release.referenced_columns} >= {
        "coarse_region",
        "customer_id",
        "purchase_amount",
    }
    assert release.aggregate_functions == ("AVG",)


def test_disclosure_event_contains_hashes_not_sql_or_literals() -> None:
    catalog = default_fixture_catalog()
    sql = "SELECT AVG(o.purchase_amount) AS avg_purchase FROM orders o"
    plan = analyze_sql(sql, dialect="duckdb")
    event = build_disclosure_event(
        identity=_identity(),
        catalog=catalog,
        query_plan=plan,
        subject_key=ColumnRef(dataset="orders", field_path="customer_id"),
        receipt_id="tj_0000000000000001",
        query_sha256=_sha(sql),
        policy_version="0.2.0",
    )

    rendered = event.model_dump_json()
    assert sql not in rendered
    assert "avg_purchase" in rendered
    assert event.query_sha256 == _sha(sql)

from __future__ import annotations

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


def test_subject_key_must_be_a_governed_identifier() -> None:
    catalog = default_fixture_catalog()

    with pytest.raises(DisclosureSemanticError, match="direct identifier or stable"):
        resolve_governed_subject_domain(
            catalog,
            subject_key=ColumnRef(dataset="orders", field_path="order_id"),
            source_datasets=("orders",),
        )


def test_subject_namespace_spans_datasets_that_share_the_identifier() -> None:
    """The namespace is (field_path, category), so the declared dataset need not be a source.

    Requiring it to be one rejected ordinary queries that reach the same subject population
    through another governed table, which blocked even the public order-count scenario.
    """

    domain = resolve_governed_subject_domain(
        default_fixture_catalog(),
        subject_key=ColumnRef(dataset="customers", field_path="customer_id"),
        source_datasets=("orders",),
    )

    assert domain.field_path == "customer_id"
    assert domain.category is SensitivityCategory.STABLE_PSEUDONYM


def test_subject_absent_from_every_source_still_fails_closed() -> None:
    """Relaxing the dataset check must not let a subject be assumed into a query."""

    catalog = FixtureCatalog.model_validate(
        {
            "version": "test",
            "datasets": {
                "people": {
                    "urn": "urn:li:dataset:people",
                    "fields": {"person_id": {"category": "STABLE_PSEUDONYM"}},
                },
                "weather": {
                    "urn": "urn:li:dataset:weather",
                    "fields": {"station": {"category": "PUBLIC_OR_LOW_RISK"}},
                },
            },
        }
    )

    with pytest.raises(DisclosureSemanticError, match="no governed subject identifier"):
        resolve_governed_subject_domain(
            catalog,
            subject_key=ColumnRef(dataset="people", field_path="person_id"),
            source_datasets=("weather",),
        )


@pytest.mark.parametrize(
    "conflicting_category",
    (
        "DIRECT_IDENTIFIER",
        "SENSITIVE_ATTRIBUTE",
        "UNCLASSIFIED",
    ),
)
def test_conflicting_or_non_identifier_subject_governance_fails_closed(
    conflicting_category: str,
) -> None:
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
                        "person_id": {"category": conflicting_category},
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


def test_semantic_release_is_alias_insensitive_and_does_not_retain_aliases() -> None:
    catalog = default_fixture_catalog()
    first_alias = "CALLER_ALIAS_A_MUST_NOT_PERSIST"
    second_alias = "CALLER_ALIAS_B_MUST_NOT_PERSIST"
    first = analyze_sql(
        f"SELECT AVG(o.purchase_amount) AS {first_alias} FROM orders o",
        dialect="duckdb",
    )
    renamed = analyze_sql(
        f"SELECT AVG(o.purchase_amount) AS {second_alias} FROM orders o",
        dialect="duckdb",
    )

    first_release = build_semantic_release(catalog, first)
    renamed_release = build_semantic_release(catalog, renamed)

    assert first_release.semantic_sha256 == renamed_release.semantic_sha256
    assert first_release.outputs == renamed_release.outputs
    assert first_release.outputs[0].sources[0].category == SensitivityCategory.SENSITIVE_ATTRIBUTE
    assert first_release.aggregate_functions == ("AVG",)
    rendered = first_release.model_dump_json()
    assert first_alias not in rendered
    assert second_alias not in rendered


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


def test_disclosure_event_excludes_sql_hash_alias_and_session_metadata() -> None:
    catalog = default_fixture_catalog()
    alias_marker = "SECRET_ALIAS_MUST_NOT_PERSIST"
    session_marker = "SECRET_SESSION_MUST_NOT_PERSIST"
    sql = f"SELECT AVG(o.purchase_amount) AS {alias_marker} FROM orders o"
    plan = analyze_sql(sql, dialect="duckdb")
    event = build_disclosure_event(
        identity=_identity(session=session_marker),
        catalog=catalog,
        query_plan=plan,
        subject_key=ColumnRef(dataset="orders", field_path="customer_id"),
        receipt_id="tj_0000000000000001",
        policy_version="0.2.0",
    )

    rendered = event.model_dump_json()
    assert sql not in rendered
    assert alias_marker not in rendered
    assert session_marker not in rendered
    assert "query_sha256" not in rendered
    assert event.audit_identity.credential_id == "credential-a"

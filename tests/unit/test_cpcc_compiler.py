from __future__ import annotations

import pytest

from toxicjoin.context.fixture import (
    FixtureCatalog,
    FixtureContextResolver,
    FixtureDataset,
    FixtureField,
)
from toxicjoin.models import ColumnRef, SensitivityCategory
from toxicjoin.repair import (
    RemediationOperator,
    TrustedQiTransformation,
    TrustedSensitiveAggregate,
    build_remediation_action,
    build_remediation_space,
    enumerate_cpcc_candidates,
)
from toxicjoin.repair.compiler import CpccCompileError, compile_cpcc_candidate
from toxicjoin.sql import analyze_sql

URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.cpcc,PROD)"
SUBJECT = ColumnRef(dataset="patients", field_path="customer_id")


def _catalog() -> FixtureCatalog:
    return FixtureCatalog(
        version="cpcc-compiler-v1",
        datasets={
            "patients": FixtureDataset(
                urn=URN,
                fields={
                    "customer_id": FixtureField(
                        category=SensitivityCategory.STABLE_PSEUDONYM,
                    ),
                    "diagnosis": FixtureField(
                        category=SensitivityCategory.SENSITIVE_ATTRIBUTE,
                    ),
                    "event_date": FixtureField(
                        category=SensitivityCategory.QUASI_IDENTIFIER,
                    ),
                    "country": FixtureField(
                        category=SensitivityCategory.PUBLIC_OR_LOW_RISK,
                    ),
                },
            )
        },
    )


def _resolution(sql: str):
    plan = analyze_sql(sql)
    resolution = FixtureContextResolver(_catalog()).resolve(plan)
    assert resolution.failures == ()
    return resolution


def _single(action):
    space = build_remediation_space((action,))
    return enumerate_cpcc_candidates(space)[0]


def test_remove_stable_identifier_removes_exact_root_projection() -> None:
    sql = "SELECT customer_id, diagnosis FROM patients"
    candidate = _single(
        build_remediation_action(RemediationOperator.REMOVE_STABLE_IDENTIFIER)
    )

    compiled = compile_cpcc_candidate(
        sql,
        candidate,
        original_resolution=_resolution(sql),
        subject_key=SUBJECT,
    )
    plan = analyze_sql(compiled.generated_sql)

    assert [item.field_path for item in plan.projected_columns] == ["diagnosis"]
    assert compiled.operations == ("REMOVE_STABLE_IDENTIFIER",)


def test_remove_sensitive_projection_preserves_identifier_projection() -> None:
    sql = "SELECT customer_id, diagnosis FROM patients"
    candidate = _single(
        build_remediation_action(RemediationOperator.REMOVE_SENSITIVE_PROJECTION)
    )

    compiled = compile_cpcc_candidate(
        sql,
        candidate,
        original_resolution=_resolution(sql),
        subject_key=SUBJECT,
    )
    plan = analyze_sql(compiled.generated_sql)

    assert [item.field_path for item in plan.projected_columns] == ["customer_id"]


def test_remove_projection_uses_governed_urn_field_key() -> None:
    sql = "SELECT customer_id, country FROM patients"
    candidate = _single(
        build_remediation_action(
            RemediationOperator.REMOVE_PROJECTION,
            field_key=f"{URN}#country",
        )
    )

    compiled = compile_cpcc_candidate(
        sql,
        candidate,
        original_resolution=_resolution(sql),
        subject_key=SUBJECT,
    )
    plan = analyze_sql(compiled.generated_sql)

    assert [item.field_path for item in plan.projected_columns] == ["customer_id"]


def test_coarsen_qi_uses_only_frozen_date_trunc_transform() -> None:
    sql = "SELECT event_date AS event_day FROM patients"
    candidate = _single(
        build_remediation_action(
            RemediationOperator.COARSEN_QI,
            field_key=f"{URN}#event_date",
            qi_transformation=TrustedQiTransformation.DATE_TO_MONTH,
        )
    )

    compiled = compile_cpcc_candidate(
        sql,
        candidate,
        original_resolution=_resolution(sql),
        subject_key=SUBJECT,
    )

    assert "DATE_TRUNC('MONTH', event_date)" in compiled.generated_sql.upper()
    assert "AS event_day" in compiled.generated_sql
    analyze_sql(compiled.generated_sql)


def test_aggregate_sensitive_replaces_simple_projection_and_preserves_alias() -> None:
    sql = "SELECT diagnosis AS diagnosis_value FROM patients"
    candidate = _single(
        build_remediation_action(
            RemediationOperator.AGGREGATE_SENSITIVE,
            field_key=f"{URN}#diagnosis",
            aggregate_operator=TrustedSensitiveAggregate.COUNT_DISTINCT,
        )
    )

    compiled = compile_cpcc_candidate(
        sql,
        candidate,
        original_resolution=_resolution(sql),
        subject_key=SUBJECT,
    )
    plan = analyze_sql(compiled.generated_sql)

    assert "COUNT(DISTINCT diagnosis)" in compiled.generated_sql
    assert "AS diagnosis_value" in compiled.generated_sql
    assert "COUNT" in plan.aggregate_functions


def test_add_minimum_group_threshold_reuses_existing_fail_closed_rewriter() -> None:
    sql = (
        "SELECT COUNT(diagnosis) AS diagnosis_count FROM patients "
        "WHERE customer_id IS NOT NULL"
    )
    candidate = _single(
        build_remediation_action(
            RemediationOperator.ADD_MINIMUM_GROUP_THRESHOLD,
            minimum_group_size=20,
        )
    )

    compiled = compile_cpcc_candidate(
        sql,
        candidate,
        original_resolution=_resolution(sql),
        subject_key=SUBJECT,
    )
    plan = analyze_sql(compiled.generated_sql)

    assert plan.minimum_group_size_present == 20
    assert plan.minimum_group_size_subject is not None
    assert plan.minimum_group_size_subject.key == SUBJECT.key


def test_increase_threshold_requires_weaker_existing_threshold() -> None:
    sql = (
        "SELECT COUNT(diagnosis) AS diagnosis_count FROM patients "
        "HAVING COUNT(DISTINCT customer_id) >= 10"
    )
    candidate = _single(
        build_remediation_action(
            RemediationOperator.INCREASE_MINIMUM_GROUP_THRESHOLD,
            minimum_group_size=20,
        )
    )

    compiled = compile_cpcc_candidate(
        sql,
        candidate,
        original_resolution=_resolution(sql),
        subject_key=SUBJECT,
    )
    assert analyze_sql(compiled.generated_sql).minimum_group_size_present == 20


def test_compiler_rejects_ambiguous_duplicate_target_projection() -> None:
    sql = "SELECT diagnosis, diagnosis FROM patients"
    candidate = _single(
        build_remediation_action(
            RemediationOperator.REMOVE_PROJECTION,
            field_key=f"{URN}#diagnosis",
        )
    )

    with pytest.raises(CpccCompileError, match="exactly one"):
        compile_cpcc_candidate(
            sql,
            candidate,
            original_resolution=_resolution(sql),
            subject_key=SUBJECT,
        )


def test_compiler_rejects_removing_every_projection() -> None:
    sql = "SELECT diagnosis FROM patients"
    candidate = _single(
        build_remediation_action(RemediationOperator.REMOVE_SENSITIVE_PROJECTION)
    )

    with pytest.raises(CpccCompileError, match="remove every projected output"):
        compile_cpcc_candidate(
            sql,
            candidate,
            original_resolution=_resolution(sql),
            subject_key=SUBJECT,
        )


def test_compiler_rejects_multiple_threshold_actions_in_one_candidate() -> None:
    sql = (
        "SELECT COUNT(diagnosis) FROM patients "
        "HAVING COUNT(DISTINCT customer_id) >= 10"
    )
    actions = (
        build_remediation_action(
            RemediationOperator.ADD_MINIMUM_GROUP_THRESHOLD,
            minimum_group_size=20,
        ),
        build_remediation_action(
            RemediationOperator.INCREASE_MINIMUM_GROUP_THRESHOLD,
            minimum_group_size=30,
        ),
    )
    space = build_remediation_space(actions)
    pair = next(candidate for candidate in enumerate_cpcc_candidates(space) if len(candidate.actions) == 2)

    with pytest.raises(CpccCompileError, match="multiple threshold"):
        compile_cpcc_candidate(
            sql,
            pair,
            original_resolution=_resolution(sql),
            subject_key=SUBJECT,
        )


def test_compiler_rejects_wildcard_profile() -> None:
    sql = "SELECT * FROM patients"
    candidate = _single(
        build_remediation_action(RemediationOperator.REMOVE_STABLE_IDENTIFIER)
    )

    with pytest.raises(CpccCompileError, match="wildcard"):
        compile_cpcc_candidate(
            sql,
            candidate,
            original_resolution=_resolution(sql),
            subject_key=SUBJECT,
        )

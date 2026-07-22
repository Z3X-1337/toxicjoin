from toxicjoin.sql import analyze_sql


def test_count_star_is_not_an_output_wildcard() -> None:
    plan = analyze_sql(
        "SELECT o.category, COUNT(*) AS order_count "
        "FROM orders o GROUP BY o.category"
    )

    assert plan.contains_wildcard is False
    assert "SELECT_STAR_REQUIRES_SCHEMA_EXPANSION" not in plan.analysis_warnings
    assert plan.aggregate_functions == ("COUNT",)


def test_unqualified_output_star_remains_flagged() -> None:
    plan = analyze_sql("SELECT * FROM orders")

    assert plan.contains_wildcard is True
    assert "SELECT_STAR_REQUIRES_SCHEMA_EXPANSION" in plan.analysis_warnings


def test_qualified_output_star_remains_flagged() -> None:
    plan = analyze_sql("SELECT o.* FROM orders o")

    assert plan.contains_wildcard is True
    assert "SELECT_STAR_REQUIRES_SCHEMA_EXPANSION" in plan.analysis_warnings

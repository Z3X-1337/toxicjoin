-- Expected ToxicJoin outcome: BLOCK
-- Reason: COMPOSITIONAL_REIDENTIFICATION_RISK
-- DuckDB execution: never called

SELECT
    c.customer_id,
    c.age_band,
    c.precise_area,
    s.case_category
FROM customers AS c
JOIN support_cases AS s
    ON c.customer_id = s.customer_id;

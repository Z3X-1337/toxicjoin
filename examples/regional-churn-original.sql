-- Expected ToxicJoin initial outcome: REWRITE
-- Reason: SMALL_GROUP_RISK
-- The analytical purpose is supported, but no trusted minimum-subject
-- threshold is present.

SELECT
    c.coarse_region,
    AVG(r.churn_score) AS average_churn,
    COUNT(DISTINCT c.customer_id) AS subject_count
FROM customers AS c
JOIN retention_scores AS r
    ON c.customer_id = r.customer_id
GROUP BY c.coarse_region
ORDER BY c.coarse_region;

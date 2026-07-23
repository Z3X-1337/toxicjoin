-- Expected ToxicJoin final outcome: ALLOW
-- The rewritten SQL is reparsed and reevaluated before execution.
-- Deterministic fixture result: three regions with 40 distinct subjects each.

SELECT
    c.coarse_region,
    AVG(r.churn_score) AS average_churn,
    COUNT(DISTINCT c.customer_id) AS subject_count
FROM customers AS c
JOIN retention_scores AS r
    ON c.customer_id = r.customer_id
GROUP BY c.coarse_region
HAVING COUNT(DISTINCT c.customer_id) >= 20
ORDER BY c.coarse_region;

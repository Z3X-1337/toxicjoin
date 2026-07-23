-- Expected ToxicJoin outcome: ALLOW
-- Reason: NO_COMPOSITIONAL_RISK
-- No rewrite is required.

SELECT
    o.category,
    COUNT(*) AS order_count
FROM orders AS o
GROUP BY o.category
ORDER BY o.category;

-- Baseline: run against your DB (replace "flows" with PG_TABLE if different).
-- psql: \i scripts/explain_baseline.sql
--
-- 1) Grouped rules (typical UI load: time window + protocols + result)
EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
SELECT
    COALESCE(NULLIF(src_group, ''), 'nogroup') AS source_group,
    COALESCE(NULLIF(dest_group, ''), 'nogroup') AS dest_group,
    array_agg(DISTINCT dest_port ORDER BY dest_port)
        FILTER (WHERE dest_port IS NOT NULL) AS dest_ports,
    direction,
    result,
    SUM(hit_count)::BIGINT AS hit_count
FROM flows
WHERE ('' = '' OR COALESCE(NULLIF(src_group, ''), 'nogroup') = '')
  AND ('' = '' OR COALESCE(NULLIF(dest_group, ''), 'nogroup') = '')
  AND (24 = 0 OR ts >= NOW() - make_interval(hours => 24))
  AND ('' = '' OR src_ip ILIKE '%' || '' || '%')
  AND ('' = '' OR dest_ip ILIKE '%' || '' || '%')
  AND ('' = '' OR CAST(dest_port AS TEXT) = '')
  AND (ARRAY['TCP','UDP']::TEXT[] IS NULL OR UPPER(COALESCE(protocol, '')) = ANY(ARRAY['TCP','UDP']::TEXT[]))
  AND ('pass' = '' OR LOWER(COALESCE(result, '')) = 'pass')
GROUP BY src_group, dest_group, direction, result
ORDER BY hit_count DESC, source_group, dest_group
LIMIT 200;

-- 2) Dropdown groups (no IP filter — heaviest path)
EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
SELECT DISTINCT g
FROM (
    SELECT unnest(COALESCE(src_groups, ARRAY[]::TEXT[])) AS g
    FROM flows
    UNION
    SELECT COALESCE(NULLIF(src_group, ''), 'nogroup') AS g
    FROM flows
) src
WHERE g IS NOT NULL AND g != ''
ORDER BY 1;

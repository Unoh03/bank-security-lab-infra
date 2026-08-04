-- Purpose: CloudFront Viewer 요청을 IP·Path·x-edge-request-id로 찾는다.
-- Replace: ${database}.${cloudfront_table}, UTC bounds, optional source_ip.
-- Normal: 승인된 Client의 예상 Method·Path·Status가 시간창에 나타남.
-- Attack/abuse: 의심 Source·Path·Status를 Edge Request ID와 함께 좁힘.
-- False positive: NAT 공유, Browser retry, CloudFront Cache Miss 재요청.
-- Runtime verification: pending; Standard Logging v2 output is JSON.
SELECT
  date,
  time,
  "c-ip" AS source_ip,
  "cs-method" AS method,
  "cs-uri-stem" AS path,
  "sc-status" AS status,
  "x-edge-request-id" AS edge_request_id,
  "cs-protocol" AS protocol,
  "time-taken" AS time_taken
FROM ${database}.${cloudfront_table}
WHERE from_iso8601_timestamp(concat(date, 'T', time, 'Z')) BETWEEN
      from_iso8601_timestamp('${start_utc}') AND
      from_iso8601_timestamp('${end_utc}')
  AND ('${source_ip}' = '' OR "c-ip" = '${source_ip}')
ORDER BY date, time;

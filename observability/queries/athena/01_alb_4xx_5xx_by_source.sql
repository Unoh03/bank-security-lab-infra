-- Purpose: ALB 4xx/5xx와 Target 응답을 Source IP 기준으로 집계한다.
-- Replace: ${database}.${alb_table}, TIMESTAMP bounds.
-- Normal: 오류가 없거나 소수의 분산된 Client 4xx만 나타남.
-- Attack/abuse: 한 Source·경로에서 4xx/5xx 또는 Target 5xx가 집중됨.
-- False positive: Health Check 전환, 배포 중 Target 교체, 잘못된 정상 Client 요청.
-- Runtime verification: pending; create the table against
-- s3://<foundation-bucket>/alb/primary/AWSLogs/<account>/elasticloadbalancing/
SELECT
  client_ip AS source_ip,
  elb_status_code,
  target_status_code,
  count(*) AS requests
FROM ${database}.${alb_table}
WHERE from_iso8601_timestamp(time) BETWEEN
      from_iso8601_timestamp('${start_utc}') AND
      from_iso8601_timestamp('${end_utc}')
  AND (
    elb_status_code >= 400 OR
    try_cast(target_status_code AS integer) >= 400
  )
GROUP BY 1, 2, 3
ORDER BY requests DESC;

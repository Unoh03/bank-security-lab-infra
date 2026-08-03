-- Purpose: 지정 시간창의 ALB 요청을 Source IP·Path·Trace ID와 함께 Timeline용으로 반환한다.
-- Source pattern: AWS Athena ALB access-log examples.
-- Official reference: https://docs.aws.amazon.com/athena/latest/ug/query-alb-access-logs-examples.html
-- Normal: 승인된 Client의 예상 Method·Path·Status가 나타남.
-- Attack/abuse: 한 Source·Path에 오류 또는 반복 요청이 집중됨.
-- False positive: Health Check, Browser retry, 배포 중 Target 교체.
-- Runtime verification: pending
SELECT
  time AS event_time,
  client_ip AS source_ip,
  request_verb AS method,
  url_extract_path(request_url) AS route,
  elb_status_code,
  target_status_code,
  trace_id
FROM ${database}.${alb_table}
WHERE from_iso8601_timestamp(time) BETWEEN
      from_iso8601_timestamp('${start_utc}') AND
      from_iso8601_timestamp('${end_utc}')
  AND ('${source_ip}' = '' OR client_ip = '${source_ip}')
ORDER BY time
LIMIT 1000;

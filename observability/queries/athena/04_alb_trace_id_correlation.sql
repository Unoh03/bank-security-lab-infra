-- Purpose: BANK request_id와 같은 ALB trace_id의 요청·Target 응답을 찾는다.
-- Replace: ${database}.${alb_table}, ${trace_id}.
-- Normal/Attack: 한 요청의 ALB 처리 결과가 BANK Audit Event와 1:1로 연결됨.
-- False positive: 없음. 단, ALB를 거치지 않아 app-* ID가 생성된 요청은 조회 불가.
-- Runtime verification: 2026-08-02 local Sanitized Bundle에서 BANK request_id와 ALB trace_id가 2건 1:1 일치함. Athena execution은 pending.
SELECT
  time,
  client_ip AS source_ip,
  request_verb,
  request_url,
  elb_status_code,
  target_status_code,
  trace_id
FROM ${database}.${alb_table}
WHERE trace_id = '${trace_id}'
ORDER BY time;

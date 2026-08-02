-- Purpose: Primary VPC의 REJECT Traffic을 Source/Destination별로 집계한다.
-- Replace: ${database}.${vpc_flow_table}, epoch-second bounds.
-- Normal: 알려진 Background Traffic의 낮은 REJECT Baseline.
-- Attack/abuse: 한 Source의 다수 Destination Port·Address 대상 REJECT 증가.
-- False positive: Node 시작·종료, ENI 교체, 일시적인 Security Group 전환.
-- Runtime verification: pending; this project stores REJECT only.
SELECT
  srcaddr,
  dstaddr,
  dstport,
  protocol,
  count(*) AS rejected_flows,
  sum(packets) AS rejected_packets
FROM ${database}.${vpc_flow_table}
WHERE start BETWEEN ${start_epoch_seconds} AND ${end_epoch_seconds}
  AND action = 'REJECT'
GROUP BY 1, 2, 3, 4
ORDER BY rejected_flows DESC;

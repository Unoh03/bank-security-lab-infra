-- Purpose: Foundation S3의 CloudFront JSON, ALB Access, VPC REJECT Log를 Athena Query Pack에서 읽을 최소 External Table을 만든다.
-- Replace: ${database}, ${security_log_bucket}, ${account_id}, ${primary_region}, and table-name placeholders.
-- Normal: DDL 실행 후 각 Table의 제한된 시간창 SELECT가 현재 S3 Object를 반환함.
-- Attack/abuse: 해당 없음. 이 파일은 탐지 Query가 아니라 Read-only Schema 등록 DDL임.
-- False positive: 잘못된 Bucket·Account·Region 또는 실제 Log Format과 다른 Schema는 0행·NULL Field·Query 오류를 만들 수 있음.
-- Runtime verification: 2026-08-02 local Sanitized sample format matched (CloudFront 8/8 fields, ALB regex matched, VPC 14 fields); Athena execution pending approval.
-- Official references:
-- https://docs.aws.amazon.com/athena/latest/ug/create-cloudfront-table-manual-json.html
-- https://docs.aws.amazon.com/athena/latest/ug/create-alb-access-logs-table.html
-- https://docs.aws.amazon.com/athena/latest/ug/vpc-flow-logs-create-table-statement.html

CREATE DATABASE IF NOT EXISTS ${database};

CREATE EXTERNAL TABLE IF NOT EXISTS ${database}.${cloudfront_table} (
  `date` string,
  `time` string,
  `c-ip` string,
  `cs-method` string,
  `cs-uri-stem` string,
  `sc-status` string,
  `x-edge-request-id` string,
  `time-taken` string
)
ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
WITH SERDEPROPERTIES (
  'paths'='date,time,c-ip,cs-method,cs-uri-stem,sc-status,x-edge-request-id,time-taken'
)
STORED AS INPUTFORMAT 'org.apache.hadoop.mapred.TextInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://${security_log_bucket}/AWSLogs/${account_id}/CloudFront/';

CREATE EXTERNAL TABLE IF NOT EXISTS ${database}.${alb_table} (
  type string,
  time string,
  elb string,
  client_ip string,
  client_port int,
  target_ip string,
  target_port int,
  request_processing_time double,
  target_processing_time double,
  response_processing_time double,
  elb_status_code int,
  target_status_code string,
  received_bytes bigint,
  sent_bytes bigint,
  request_verb string,
  request_url string,
  request_proto string,
  user_agent string,
  ssl_cipher string,
  ssl_protocol string,
  target_group_arn string,
  trace_id string,
  domain_name string,
  chosen_cert_arn string,
  matched_rule_priority string,
  request_creation_time string,
  actions_executed string,
  redirect_url string,
  lambda_error_reason string,
  target_port_list string,
  target_status_code_list string,
  classification string,
  classification_reason string,
  conn_trace_id string
)
ROW FORMAT SERDE 'org.apache.hadoop.hive.serde2.RegexSerDe'
WITH SERDEPROPERTIES (
  'serialization.format' = '1',
  'input.regex' = '([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*):([0-9]*) ([^ ]*)[:-]([0-9]*) ([-.0-9]*) ([-.0-9]*) ([-.0-9]*) (|[-0-9]*) (-|[-0-9]*) ([-0-9]*) ([-0-9]*) "([^ ]*) (.*) (- |[^ ]*)" "([^"]*)" ([A-Z0-9-_]+) ([A-Za-z0-9.-]*) ([^ ]*) "([^"]*)" "([^"]*)" "([^"]*)" ([-.0-9]*) ([^ ]*) "([^"]*)" "([^"]*)" "([^ ]*)" "([^\\s]+?)" "([^\\s]+)" "([^ ]*)" "([^ ]*)" ?([^ ]*)? ?( .*)?'
)
LOCATION 's3://${security_log_bucket}/alb/primary/AWSLogs/${account_id}/elasticloadbalancing/${primary_region}/';

-- Runtime Source uses the default 14-field VPC Flow Log v2 text format.
CREATE EXTERNAL TABLE IF NOT EXISTS ${database}.${vpc_flow_table} (
  version int,
  account_id string,
  interface_id string,
  srcaddr string,
  dstaddr string,
  srcport int,
  dstport int,
  protocol bigint,
  packets bigint,
  bytes bigint,
  start bigint,
  `end` bigint,
  action string,
  log_status string
)
ROW FORMAT DELIMITED
FIELDS TERMINATED BY ' '
LOCATION 's3://${security_log_bucket}/vpc-flow/AWSLogs/${account_id}/vpcflowlogs/${primary_region}/'
TBLPROPERTIES ('skip.header.line.count'='1');

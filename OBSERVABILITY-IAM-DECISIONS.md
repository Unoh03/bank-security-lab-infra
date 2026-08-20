# 근실시간 관제·S3 로그 분석·Pod Identity 결정 기준

> 상태: **현재 Runtime 반영 / Live Tail Viewer 계획 추가 / 추가 AWS 변경 없음**  
> 기준 시점: 2026-08-06  
> 실행 순서: [`OBSERVABILITY-IAM-IMPLEMENTATION-PLAN.md`](./OBSERVABILITY-IAM-IMPLEMENTATION-PLAN.md)

이 문서는 처음 전달받은 요구사항과 이후 확인된 사용 목적을 기준으로 범위와 성공 조건을 고정한다. Source가 존재하는 상태, 실제 Runtime에서 확인한 상태, 앞으로 구현할 상태를 섞지 않는다.

---

## 1. 원래 요구사항과 사용자 의도

```text
S3 로그 분석 (AWS Grafana를 활용해서 시각화)
EKS 각각의 POD들의 IAM 권한 설정 (pod identity)
리소스별로 로그저장 S3 구분
구성하고 구성된 결과를 듣고 보는 것
```

추가로 확인된 시각화 목적:

> 공격을 수행하는 동안 관제 화면을 켜 두고, 탐지 이벤트가 발생하면 사람이 읽을 수 있는 형태로 바로 확인한다.

따라서 저장된 로그를 나중에 조회하는 화면만으로는 시각화 목표를 충족하지 않는다. 사후 분석과 근실시간 관제를 서로 다른 계층으로 설계한다.

---

## 2. 최종 역할 분리

```text
근실시간 관제 Dashboard
WAF·DVWA·EKS 등 CloudWatch Logs
→ Local Docker Grafana CloudWatch Data Source
→ 5초 Auto Refresh

즉시성 우선 Event Feed
CloudWatch Logs
→ CloudWatch Live Tail
→ Local Readable Live Tail Viewer

사후 분석·Evidence
CloudFront·ALB·VPC 로그
→ Security Log S3
→ Athena
→ Grafana 또는 .\daily-down.ps1 -EvidenceOnly
```

| 계층 | 목적 | 현재 상태 |
|---|---|---|
| Grafana + CloudWatch Logs Insights | 읽기 쉬운 Dashboard와 집계 | WAF Runtime 확인 |
| CloudWatch Live Tail | 새 Event를 Polling 없이 Streaming | 계획 추가, Runtime 미검증 |
| S3 + Athena | 상세 조사·상관분석·Evidence | 연결과 Table 목록 확인 |

`실시간`은 무지연을 의미하지 않는다. 현재 Grafana 경로는 5초 Auto Refresh에서 약 10초의 전체 표시 지연을 직접 관측했다. Live Tail의 실제 지연은 별도 Runtime Test에서 측정한다.

---

## 3. 현재 확인된 사실

### 3.1 로컬 Grafana와 Athena

```text
Browser
→ http://127.0.0.1:3000
→ Local Docker Grafana
→ Amazon Athena plugin 3.2.0
→ Credentials file profile: terra-user
→ AwsDataCatalog
→ aws_topology_security
→ Workgroup: primary
```

직접 확인:

- Athena Data Source의 `Data source is working`
- Catalog `AwsDataCatalog`
- Database `aws_topology_security`
- Table 목록

```text
alb_primary_access
cloudfront_access
vpc_reject
```

아직 확인하지 않은 것:

- 세 Table의 실제 로그 행과 Schema 품질
- S3 Source별 최신 Object
- Athena 기반 최종 조사 Panel과 Dashboard JSON

### 3.2 로컬 Grafana와 CloudWatch WAF

직접 확인된 경로:

```text
통제된 XSS·SQLi Request
→ CloudFront WAF
→ CloudWatch Logs
→ Local Grafana CloudWatch Data Source
→ Auto Refresh로 Event 표시
```

확인값:

| 항목 | 결과 |
|---|---|
| CloudWatch Metrics API | 연결 성공 |
| CloudWatch Logs API | 연결 성공 |
| WAF Region | `us-east-1` |
| WAF Log Group | `aws-waf-logs-aws-topology-edge` |
| Auto Refresh | `5s` |
| 관측된 전체 표시 지연 | 대략 10초 |
| XSS 탐지 | `CrossSiteScripting_QUERYARGUMENTS`, COUNT, 최종 ALLOW |
| SQLi 요청 | WAF Event가 자동 표시되는 것 확인 |

현재 WAF Managed Rule은 Training Application을 계속 사용할 수 있도록 COUNT Mode다. 탐지는 기록되지만 Web ACL의 최종 처리 결과는 ALLOW일 수 있다.

Obsidian Runtime Note:

```text
10_학습 노트/클라우드/Grafana 로컬 Docker에서 CloudWatch WAF 근실시간 관제.md
```

### 3.3 CloudWatch Live Tail

확인된 기술 조건:

- Live Tail은 Log Group에 새로 수집되는 Event를 Streaming한다.
- CLI Session은 `logs:StartLiveTail` 권한이 필요하다.
- Console 사용까지 고려한 Read Policy에는 `logs:StartLiveTail`, `logs:StopLiveTail`을 포함한다.
- Log Group ARN은 `:*` 없이 전달해야 한다.
- 한 Session은 최대 3시간이다.
- Live Tail은 Standard Log Class에서만 사용할 수 있다.
- Session 사용 시간(분)을 기준으로 과금되므로 공격 실험·발표 시간에만 실행한다.

현재 상태:

```text
CLI Permission Test       NotRun
Live Tail Runtime         NotRun
Readable Local Viewer     NotImplemented
Terraform Change          NotRequiredUntilAccessDenied
```

Live Tail 자체는 새 AWS Resource를 생성하지 않는다. 기존 `terra-user`로 CLI Test가 성공하면 Terraform 변경 없이 Local Viewer를 구현한다. `AccessDenied`가 발생할 때만 현재 Credential의 관리 경계를 확인하고 최소 권한 변경안을 작성한다.

### 3.4 현재 S3 로그 분리 구조

| Source | 현재 저장 위치 | 역할 |
|---|---|---|
| CloudFront Access Log | `AWSLogs/<ACCOUNT_ID>/CloudFront/` | 사후 분석 |
| Primary ALB Access Log | `alb/primary/AWSLogs/<ACCOUNT_ID>/elasticloadbalancing/ap-northeast-2/` | 사후 분석 |
| Primary VPC REJECT Flow Log | `vpc-flow/AWSLogs/<ACCOUNT_ID>/vpcflowlogs/ap-northeast-2/` | 사후 분석 |
| CloudTrail | `AWSLogs/<ACCOUNT_ID>/CloudTrail/` | 보조 Evidence |
| Athena Query Result | `athena-results/...` | 분석 결과, 원본 아님 |

현재는 하나의 Foundation Security Log Bucket 안에서 Prefix와 Bucket Policy Resource 범위로 Source를 구분한다.

### 3.5 현재 Pod Identity Source

| Workload | Cluster | Namespace / ServiceAccount | Source | 현재 판정 |
|---|---|---|---|---|
| AWS Load Balancer Controller | Primary / DR | `kube-system/aws-load-balancer-controller` | `cluster-controllers.tf` | Source 구성, Runtime 재검증 필요 |
| ExternalDNS | Primary / 조건부 DR | `external-dns/external-dns` | `cluster-controllers.tf` | 조건부 Source 구성, Runtime 재검증 필요 |
| EFS CSI Controller | Primary / DR | `kube-system/efs-csi-controller-sa` | `storage-access.tf`, `eks.tf` | Source 구성, Runtime 재검증 필요 |
| Web S3 Workload | Primary / 조건부 DR | `var.web_namespace/var.web_service_account` | `storage-access.tf` | Source 구성, Runtime 재검증 필요 |
| Fluent Bit DVWA Log Forwarder | Primary / 조건부 DR | `amazon-cloudwatch/aws-for-fluent-bit` | `observability.tf` | 조건부 Source 구성, Runtime 재검증 필요 |
| Karpenter Controller | Primary / 조건부 DR | Module 생성 Association | `eks.tf` | Source 구성, Runtime Inventory 필요 |

---

## 4. 결정표

| ID | 결정 | 상태 | 결론 |
|---|---|---|---|
| D01 | 시각화 목표 | 확정 | 공격 중 Event가 자동으로 나타나는 근실시간 관제를 핵심 범위에 포함한다. |
| D02 | 관제 구조 | 확정 | Grafana는 읽기 쉬운 Dashboard, Live Tail은 즉시성 우선 Event Feed, Athena는 사후 분석을 담당한다. |
| D03 | Grafana 운영 방식 | Runtime 확인 | Local Docker Grafana를 사용한다. 특정 Managed Grafana 제품은 필수가 아니다. |
| D04 | Grafana 갱신 | Runtime 확인 | CloudWatch Logs Panel은 5초 Auto Refresh를 사용했고 약 10초 지연을 관측했다. 더 짧은 주기보다 Query 비용·가독성을 우선한다. |
| D05 | Live Tail 도입 | 확정 | WAF Log Group을 대상으로 Permission·Runtime을 먼저 검증하고, 성공하면 읽기 쉬운 Local Viewer를 구현한다. |
| D06 | Live Tail와 Terraform | 확정 | Live Tail CLI가 성공하면 Terraform을 수정하지 않는다. AccessDenied일 때만 최소 권한 Plan을 작성한다. |
| D07 | Codex 역할 | 확정 | Repository·Credential 경계를 검토하고 Live Tail Viewer, Test, 문서를 구현한다. 필요성 확인 전 IAM·Terraform을 변경하지 않는다. |
| D08 | Live Tail Viewer 출력 | 확정 | Timestamp, 탐지 유형, Rule, COUNT/BLOCK, 최종 Action, Country, Source IP, Method, Host, URI, Args를 한 행으로 표시한다. |
| D09 | Live Tail 비용 통제 | 확정 | Session은 공격 실험·발표 중에만 실행하고 종료 시 연결을 닫는다. 현재 AWS Pricing을 실행 전 확인한다. |
| D10 | S3 분석 Source | 확정 | CloudFront, Primary ALB, Primary VPC REJECT를 Athena 1차 대상으로 유지한다. |
| D11 | 로그 저장 분리 | 잠정 | 현재는 Security Log Bucket 하나와 Source별 Prefix를 사용한다. 별도 Bucket 요구가 확인될 때만 변경한다. |
| D12 | Athena 역할 | 확정 | 실시간 관제가 아니라 상세 조사·상관분석·Evidence를 담당한다. |
| D13 | Pod Identity 단위 | 기술 기준 | `Cluster + Namespace + ServiceAccount → IAM Role` 단위로 관리한다. |
| D14 | Pod Identity 완료 조건 | Runtime Gate | 실제 Pod STS Role, 허용 API 성공, 비허용 API 거부, Node Role 비노출을 확인한다. |
| D15 | 결과 증명 | 확정 | Source·Runtime·Evidence를 분리하고 Screenshot, Query, Viewer 출력, Pod Identity 결과를 보존한다. |
| D16 | 변경 통제 | 확정 | Read-only Test 전에 새 AWS Resource, IAM 변경, Terraform Apply, Kubernetes Mutation을 하지 않는다. |
| D17 | 중앙 관제 제품 | 확정 | Wazuh를 SIEM으로 사용하고 별도 Elastic Security·ELK Stack은 함께 구축하지 않는다. |
| D18 | Wazuh 배치 | Local Runtime 기동 확인 | Local Docker single-node를 사용한다. Wazuh 4.14.7 Manager·Indexer·Dashboard와 Docker·WSL 사전 조건을 확인했으며 AWS 원본 입력은 아직 연결하지 않았다. |
| D19 | Wazuh 원본 입력 | 확정 | CloudTrail은 Security Log S3, WAF와 Primary DVWA는 기존 CloudWatch Logs에서 직접 읽는다. CloudWatch Alarm State Change를 SIEM 입력으로 사용하지 않는다. |
| D20 | AWS Native 경보 | 확정 | 기존 Metric Filter→CloudWatch Alarm→SNS는 사람 알림과 독립 검증 경로로 유지한다. |
| D21 | SIEM→SOAR | 확정 | GT-03을 통과한 고신뢰 S3 Custom Alert만 Shuffle 자동 대응 입력으로 사용한다. Rule `100103`은 조기 경보 observe-only이며 자동 격리 입력에서 제외한다. 같은 사건을 CloudWatch에서도 Shuffle로 중복 전송하지 않는다. |
| D22 | Wazuh IAM | Apply·Runtime Trust 검증 완료 | 기본 비활성 전용 Read-only Role만 Terraform으로 만들고 장기 Access Key·User·Credential은 만들지 않는다. 2 Add, 0 Change, 0 Destroy Apply와 실제 네 Read Action, AssumeRole, Post-Apply 0-change를 확인했다. |
| D23 | Wazuh 원본 보존 | Runtime Gate | Scoped Source의 `wazuh-archives-*`와 Docker Volume을 사용하고 재시작 뒤 설정·Rule·Event 보존을 증명한다. |
| D24 | Wazuh 최초 수집 경계 | 확정 | 첫 AWS 모듈 실행 전에 `only_logs_after=2026-AUG-12`, 승인 Account ID, Source별 Region을 고정한다. 뒤늦은 범위 변경·무계획 `reparse`로 인한 누락·중복 Alert를 피한다. |

---

## 5. 열린 결정

### A01 — S3 구분의 합격 기준

현재 구현은 한 Bucket의 Prefix 분리다. 평가자가 리소스별 별도 Bucket을 명시적으로 요구할 때만 Migration을 계획한다.

### A02 — Live Tail Viewer 구현 방식

Codex가 현재 Windows·PowerShell·Docker 환경과 AWS CLI/SDK 호환성을 확인한 뒤 다음 중 최소 복잡도 방식을 선택한다.

```text
PowerShell Wrapper
Python/boto3 Streaming Viewer
작은 Local Web UI
```

선정 기준:

```text
Event 누락 없이 지속 수신
Ctrl+C 또는 UI 종료 시 Session 종료
WAF JSON Field 정규화
민감정보 저장 금지
설치·실행 절차 재현 가능
Terraform 변경 최소화
```

### A03 — DR Pod Identity 증명 범위

Primary와 DR을 모두 시연해야 하는지는 Runtime 활성 상태와 평가 기준을 보고 결정한다.

### A04 — Wazuh 임시 Credential 갱신 방식

기본안은 Host에서 Wazuh Reader Role의 임시 STS Session을 발급하고 Git 밖의 임시
Credential 파일을 Wazuh Manager에 Read-only Mount하는 방식이다. 광범위한 기존
`terra-user` Profile 전체를 Container에 노출하지 않는다. Gate 4 Preflight에서 Session
만료 전 갱신·재시작 절차를 검증하며, 이 방식이 운영 시간을 충족하지 못할 때만
IAM Roles Anywhere 또는 AWS 배치를 후속 대안으로 검토한다.

### A05 — Wazuh Archives 보존 기간

원본 검색을 위해 `wazuh-archives-*`를 활성화하되 무기한 보존하지 않는다. 세 Project
Source를 연결한 뒤 하루 Index 크기를 측정하고, 핵심 시연 기간을 포함하는 가장 짧은
보존 기간을 확정한다.

---

## 6. 완료 조건

### 근실시간 관제

- Grafana CloudWatch Data Source 연결과 WAF Panel 자동 갱신
- XSS·SQLi Event가 사용자 입력 없이 자동 표시
- 실제 표시 지연 측정
- Raw JSON이 아니라 주요 Field가 읽기 쉬운 형태로 표시
- Live Tail Permission·Runtime Test 성공
- Local Viewer가 새 Event를 Streaming하고 정상 종료

### S3·Athena 사후 분석

- 세 필수 Prefix의 실제 Object 확인
- Athena Table LOCATION과 Prefix 일치
- 실제 행 반환과 Schema 품질 확인
- 조사 Query와 Evidence 보존

### Pod Identity

- Source와 AWS Association Inventory 일치
- Association과 실제 ServiceAccount 일치
- 예상 STS Role과 대표 허용 API 확인
- 비허용 API와 Node Role 노출 Negative Test

---

## 7. 핵심 범위 완료 전 보류

```text
Grafana Cloud 재시도
Amazon Managed Grafana
GuardDuty → EventBridge → SNS
Grafana Alert Rule
자동 격리·자동 차단
별도 Athena Result Bucket
Source별 S3 Bucket Migration
```

---

## 8. Source of Truth

| 영역 | 현재 파일 |
|---|---|
| Security Log Bucket·Lifecycle·Bucket Policy | `foundation/observability.tf`, `foundation/variables.tf` |
| CloudFront·VPC REJECT·WAF·Fluent Bit | `observability.tf` |
| Athena DDL·S3 LOCATION | `observability/queries/athena/00_create_security_log_tables.sql` |
| Athena Query Runner | `observability/Invoke-AthenaQueryPack.ps1` |
| LBC·ExternalDNS Pod Identity | `cluster-controllers.tf` |
| EFS CSI·Web S3 Pod Identity | `storage-access.tf`, `eks.tf` |
| Karpenter Pod Identity | `eks.tf` |
| 실행 순서·Live Tail Gate | `OBSERVABILITY-IAM-IMPLEMENTATION-PLAN.md` |
| Wazuh SIEM·SOAR 전체 흐름 | `CAPITAL-ONE-SOC-DEMO-PLAN.md` |
| Capital One 대응 의미·단계 구분 | `CAPITAL-ONE-INCIDENT-RESPONSE-SCENARIO.md` |
| Wazuh Reader Terraform 경계 | `CAPITAL-ONE-SOC-TERRAFORM-IMPLEMENTATION-PLAN.md` |

---

## 9. 참고 자료

- CloudWatch Logs Live Tail: https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CloudWatchLogs_LiveTail.html
- AWS CLI `start-live-tail`: https://docs.aws.amazon.com/cli/latest/reference/logs/start-live-tail.html
- CloudWatch Logs IAM: https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/iam-identity-based-access-control-cwl.html
- Amazon Athena Data Source for Grafana: https://grafana.com/docs/plugins/grafana-athena-datasource/latest/
- Grafana CloudWatch Data Source: https://grafana.com/docs/grafana/latest/datasources/aws-cloudwatch/
- Amazon EKS Pod Identity: https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html
- Wazuh Docker deployment: https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html
- Wazuh AWS CloudTrail: https://documentation.wazuh.com/current/cloud-security/amazon/services/supported-services/cloudtrail.html
- Wazuh AWS CloudWatch Logs: https://documentation.wazuh.com/current/cloud-security/amazon/services/supported-services/cloudwatchlogs.html
- Wazuh AWS module configuration: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-s3.html
- Wazuh AWS module filtering and reparse: https://documentation.wazuh.com/current/cloud-security/amazon/services/prerequisites/considerations.html
- Wazuh custom rules: https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html
- Wazuh all-event archives: https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html
- Wazuh Shuffle integration: https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html

# Observability·S3 로그·Pod Identity 결정 기준

> 상태: **기준 재정립 / 현재 Runtime 사실 반영 / 추가 AWS 변경 없음**  
> 기준 시점: 2026-08-06  
> 실행 순서: [`OBSERVABILITY-IAM-IMPLEMENTATION-PLAN.md`](./OBSERVABILITY-IAM-IMPLEMENTATION-PLAN.md)

이 문서는 처음 전달받은 요구사항을 기준으로 범위와 성공 조건을 다시 고정한다. 기존의 Grafana Cloud 중심 계획을 현재 실제로 검증된 로컬 Grafana 경로와 분리하고, 아직 확인하지 않은 사항을 완료로 기록하지 않는다.

---

## 1. 원래 요구사항

```text
S3 로그 분석 (AWS Grafana를 활용해서 시각화)
EKS 각각의 POD들의 IAM 권한 설정 (pod identity)
리소스별로 로그저장 S3 구분
구성하고 구성된 결과를 듣고 보는 것
```

이 네 항목이 핵심 범위다. CloudWatch 관제, EventBridge 알림, 자동 대응, Amazon Managed Grafana 학습은 핵심 범위를 완료한 뒤 별도로 판단한다.

---

## 2. 요구사항 해석 기준

| 원문 | 현재 해석 | 주의점 |
|---|---|---|
| `AWS Grafana` | AWS의 S3·Athena 데이터를 Grafana에서 시각화 | 원문만으로 Amazon Managed Grafana 사용이 필수라고 단정하지 않는다. 현재 검증된 경로는 로컬 Docker Grafana다. |
| `각각의 POD들의 IAM 권한` | `Cluster + Namespace + ServiceAccount → IAM Role` 단위의 EKS Pod Identity | Pod Replica마다 별도 IAM Role을 만들지 않는다. 같은 ServiceAccount를 쓰는 Pod는 같은 Workload Identity를 공유한다. |
| `리소스별로 로그저장 S3 구분` | 현재는 Security Log Bucket 하나에서 Source별 Prefix로 구분 | 별도 Bucket이 필수라는 뜻인지, Prefix 구분으로 충분한지는 최종 평가 기준을 확인해야 한다. |
| `결과를 듣고 보는 것` | 구성 설명, 실제 Query 결과, Grafana 화면, Pod 내부 권한 검증 Evidence | Terraform Source가 존재하는 것만으로 완료로 판정하지 않는다. |

---

## 3. 현재 확인된 사실

### 3.1 S3·Athena·Grafana

현재 로컬 PC에서 Docker Grafana를 실행하고 Amazon Athena Data Source를 연결했다.

```text
Browser
→ http://127.0.0.1:3000
→ Local Docker Grafana
→ Amazon Athena plugin 3.2.0
→ Credentials file profile: terra-user
→ AwsDataCatalog
→ aws_topology_security
→ Workgroup: primary
→ Security Log Bucket의 athena-results/grafana/ Prefix
```

직접 확인된 사항:

- Grafana `Save & test`에서 `Data source is working` 확인
- Athena Catalog `AwsDataCatalog` 확인
- Database `aws_topology_security` 확인
- 다음 세 Table의 목록 조회 성공

```text
alb_primary_access
cloudfront_access
vpc_reject
```

아직 완료로 판정하지 않는 사항:

- 세 Table 각각에서 실제 S3 로그 행이 반환되는지
- 세 Source의 최신 S3 Object가 실제로 존재하는지
- Grafana Dashboard Panel이 실제 데이터로 표시되는지
- Dashboard JSON과 최종 Evidence Bundle

로컬 Grafana 재현 절차와 성공 화면은 Obsidian의 다음 노트에 기록되어 있다.

```text
10_학습 노트/클라우드/Grafana 로컬 Docker에서 Athena 연결.md
```

### 3.2 현재 S3 로그 분리 구조

`foundation/observability.tf`와 `observability.tf`의 현재 구조는 다음과 같다.

| Source | 현재 저장 위치 | 핵심 범위 |
|---|---|---:|
| CloudFront Access Log | `AWSLogs/<ACCOUNT_ID>/CloudFront/` | 필수 |
| Primary ALB Access Log | `alb/primary/AWSLogs/<ACCOUNT_ID>/elasticloadbalancing/ap-northeast-2/` | 필수 |
| Primary VPC REJECT Flow Log | `vpc-flow/AWSLogs/<ACCOUNT_ID>/vpcflowlogs/ap-northeast-2/` | 필수 |
| CloudTrail | `AWSLogs/<ACCOUNT_ID>/CloudTrail/` | 보조 |
| Athena Query Result | `athena-results/...` | 분석 결과, 원본 로그 아님 |

현재는 하나의 Foundation Security Log Bucket을 사용하고 Prefix와 Bucket Policy Resource 범위로 Source를 구분한다.

### 3.3 현재 Pod Identity Source

Source에 정의된 Workload Identity는 다음과 같다. Source 존재와 Runtime 검증 완료를 구분한다.

| Workload | Cluster | Namespace / ServiceAccount | Source | 현재 판정 |
|---|---|---|---|---|
| AWS Load Balancer Controller | Primary / DR | `kube-system/aws-load-balancer-controller` | `cluster-controllers.tf` | Source 구성, Runtime 재검증 필요 |
| ExternalDNS | Primary / 조건부 DR | `external-dns/external-dns` | `cluster-controllers.tf` | 조건부 Source 구성, Runtime 재검증 필요 |
| EFS CSI Controller | Primary / DR | `kube-system/efs-csi-controller-sa` | `storage-access.tf`, `eks.tf` | Source 구성, Runtime 재검증 필요 |
| Web S3 Workload | Primary / 조건부 DR | `var.web_namespace/var.web_service_account` | `storage-access.tf` | Source 구성, Runtime 재검증 필요 |
| Fluent Bit DVWA Log Forwarder | Primary / 조건부 DR | `amazon-cloudwatch/aws-for-fluent-bit` | `observability.tf` | 조건부 Source 구성, Runtime 재검증 필요 |
| Karpenter Controller | Primary / 조건부 DR | Module 생성 Association | `eks.tf` | Source 구성, 실제 ServiceAccount·Role Inventory 필요 |

EKS에는 `eks-pod-identity-agent` Add-on이 Source에 포함되어 있다. 실제 Cluster, Association, Pod, ServiceAccount, IAM Role의 일치 여부는 Runtime에서 다시 검증한다.

---

## 4. 결정표

| ID | 결정 | 상태 | 결론 |
|---|---|---|---|
| D01 | 핵심 범위 | 확정 | 처음 전달받은 네 요구사항만 우선 완료한다. 근실시간 관제와 알림은 후속 범위다. |
| D02 | 현재 Grafana 실행 방식 | Runtime 확인 | 현재 기준 구현은 로컬 Docker Grafana다. Grafana Cloud 경로는 플러그인 설정 오류로 중단했고 기본 계획에서 제외한다. |
| D03 | Amazon Managed Grafana | 미확정·후속 | 원문에서 필수 제품으로 확인되지 않았다. 평가자가 명시적으로 요구할 때 별도 계획을 작성한다. |
| D04 | 필수 S3 분석 Source | 확정 | CloudFront, Primary ALB, Primary VPC REJECT 세 Source를 1차 완료 대상으로 한다. |
| D05 | CloudTrail 분석 | 후속 | S3에는 저장되지만 현재 Athena Table과 필수 Grafana Panel 범위에서는 제외한다. |
| D06 | 로그 저장 분리 방식 | 잠정 | 현재는 Security Log Bucket 하나와 Source별 Prefix를 사용한다. 별도 Bucket 필수 여부는 평가 기준 확인 전까지 열린 결정으로 둔다. |
| D07 | 원본 로그 보존 | Source 확인 | 현재 Security Log Bucket Lifecycle은 전체 Object에 30일을 적용한다. |
| D08 | Athena 결과 보존 | 현재 사실 반영 | 현재 Query Result도 같은 Bucket의 `athena-results/` Prefix에 저장되어 30일 Lifecycle을 따른다. 기존 문서의 별도 Result Bucket 7일 계획은 구현되지 않았고 현재 기본 경로가 아니다. |
| D09 | 로컬 Grafana AWS 인증 | Runtime 확인 | Windows `.aws`를 컨테이너의 `/home/grafana/.aws`에 Read-only Mount하고 `terra-user` Profile을 사용한다. 장기적으로 전용 최소 권한 Profile 분리를 검토한다. |
| D10 | Grafana 구성 방식 | 확정 | 먼저 UI에서 실제 Query와 Panel을 검증하고, 성공 후 Dashboard JSON을 Export한다. Grafana Provider 자동화는 후속이다. |
| D11 | Pod Identity 단위 | 기술 기준 | `Cluster + Namespace + ServiceAccount → IAM Role` 단위로 관리한다. Pod 개별 Role은 만들지 않는다. |
| D12 | Pod Identity 완료 조건 | Runtime Gate | Association 존재, 실제 Pod ServiceAccount, 예상 STS Role, 허용 API 성공, 비허용 API 거부를 모두 확인한다. |
| D13 | Node Role 노출 | Runtime Gate | Association 없는 ServiceAccount가 Node Role을 획득하는지 검사한다. 반환되면 완료로 판정하지 않고 별도 Hardening Plan을 작성한다. |
| D14 | 결과 증명 | 확정 | Source·Plan·Runtime·Evidence를 구분하고 Query 결과, Grafana 화면, IAM 검증 결과를 보존한다. |
| D15 | 변경 통제 | 확정 | Inventory와 Read-only 검증 전에 새 Bucket, Grafana 서비스, IAM Role, Pod Identity Association을 추가하지 않는다. `terraform apply`와 `kubectl` Mutation은 사용자 승인 뒤 수행한다. |

---

## 5. 열린 결정

### A01 — S3 구분의 합격 기준

현재 구현은 한 Bucket의 Prefix 분리다.

```text
Security Log Bucket
├─ AWSLogs/.../CloudFront/
├─ alb/primary/AWSLogs/.../
├─ vpc-flow/AWSLogs/.../
└─ AWSLogs/.../CloudTrail/
```

평가자가 `리소스별 별도 Bucket`을 요구한다면 현재 구조는 변경이 필요하다. 평가자가 논리적 분리, Prefix, IAM Policy 범위 분리를 인정한다면 현재 구조를 유지한다.

### A02 — Grafana 제품의 합격 기준

현재 구현은 로컬 Grafana가 AWS Athena를 조회하는 방식이다. `Amazon Managed Grafana`가 필수라는 명시적 근거가 확인되면 별도 Workspace·인증·비용 계획을 작성한다. 근거가 없으면 현재 로컬 Grafana를 기준으로 완료한다.

### A03 — DR도 필수 증명 대상인지

원래 요구사항은 EKS Pod Identity를 말하지만 Primary와 DR을 모두 시연해야 하는지는 명시하지 않았다. Source는 DR을 조건부로 포함한다. 최종 Evidence 범위는 Runtime 활성 상태와 평가 기준을 보고 결정한다.

---

## 6. 핵심 완료 조건

### S3 로그 분석·Grafana

- 필수 세 Prefix에서 실제 S3 Object 확인
- Athena Table `LOCATION`과 실제 Prefix 일치
- 각 Table의 제한된 Query가 실제 행을 반환
- Grafana에 CloudFront, ALB, VPC REJECT Panel 구성
- Dashboard JSON과 성공 화면 보존
- Query 시간 범위와 Scan 범위를 제한

### Pod Identity

- Source와 AWS Association Inventory 일치
- Association과 실제 Pod ServiceAccount 일치
- Pod 내부 STS Identity가 예상 Role과 일치
- 대표 허용 API 성공
- 대표 비허용 API가 `AccessDenied`
- Association 없는 Pod가 Node Role을 얻지 않음

### 결과 설명·시연

- 구성도 또는 데이터 흐름 설명
- 리소스별 저장 위치 표
- Grafana Query와 Panel 화면
- Pod Identity Matrix와 Runtime 결과
- 실패·미관측·미실행을 완료와 분리

---

## 7. 핵심 범위 완료 전 보류

```text
Grafana Cloud 재시도
Amazon Managed Grafana
별도 Athena Result Bucket
Grafana Provider 자동화
CloudWatch Data Source Dashboard
GuardDuty → EventBridge → SNS
WAF·DVWA 근실시간 Alert
자동 격리·자동 차단
Source별 S3 Bucket Migration
```

이 항목들은 유효할 수 있지만 처음 요구사항보다 앞서 구현하지 않는다.

---

## 8. Source of Truth

| 영역 | 현재 파일 |
|---|---|
| Security Log Bucket·Lifecycle·Bucket Policy | `foundation/observability.tf`, `foundation/variables.tf` |
| CloudFront·VPC REJECT·WAF·Fluent Bit | `observability.tf` |
| Primary ALB Access Log | ALB 관련 Terraform Source와 `foundation/observability.tf` Bucket Policy |
| Athena DDL·S3 LOCATION | `observability/queries/athena/00_create_security_log_tables.sql` |
| Athena Query Runner | `observability/Invoke-AthenaQueryPack.ps1` |
| LBC·ExternalDNS Pod Identity | `cluster-controllers.tf` |
| EFS CSI·Web S3 Pod Identity | `storage-access.tf`, `eks.tf` |
| Karpenter Pod Identity | `eks.tf` |
| 실행 순서·Gate | `OBSERVABILITY-IAM-IMPLEMENTATION-PLAN.md` |

---

## 9. 참고 자료

- Amazon Athena Data Source for Grafana: https://grafana.com/docs/plugins/grafana-athena-datasource/latest/
- Grafana Docker 설치: https://grafana.com/docs/grafana/latest/setup-grafana/installation/docker/
- Amazon EKS Pod Identity: https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html
- Application Load Balancer Access Logs: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html
- VPC Flow Logs to Amazon S3: https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-s3.html

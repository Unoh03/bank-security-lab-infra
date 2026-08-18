# Wazuh 저지연 Push 전달 설계

> **상태:** Implementation v0.3 — Primary DVWA AWS·Local P1 Runtime 3회 완료, 실제 공격·Poll Cutover 대기
>
> **기준일:** 2026-08-17
>
> **최종 범위:** Capital One 기반 대표 시나리오의 CloudFront·WAF·ALB·DVWA·CloudTrail 5개 Source
>
> **현재 구현 범위:** Primary DVWA 1개 Source만 `CloudWatch Logs → Lambda → 서울 SQS → Local Bridge → Wazuh JSONL·Rule`
>
> **대응 의미 정본:** [`CAPITAL-ONE-INCIDENT-RESPONSE-SCENARIO.md`](../../CAPITAL-ONE-INCIDENT-RESPONSE-SCENARIO.md). 이 문서는 전달·탐지까지만 정의하며 Containment·Remediation을 재정의하지 않는다.

## 1. 결론

현재 10분 Wazuh Polling은 **이미 저장된 로그를 중앙에서 모으는 As-built**로는 유효하지만,
최초 의심 행위를 빠르게 알리는 Target Architecture로는 부족하다.

목표 구조는 다음 네 경로를 분리한다.

```text
빠른 의심    DVWA·WAF → CloudWatch Logs Subscription → Regional Lambda → Regional SQS
침해 확인    CloudTrail CloudWatch Logs ──────────────→ Regional Lambda → Regional SQS
경로 복원    ALB S3 ObjectCreated ─────────────────────────────────────→ Regional SQS
보존·재분석  기존 CloudWatch Logs·Security Log S3를 변경 없이 유지

Regional SQS 2개
→ Local Bridge가 Queue별 20초 Long Poll
→ Host Event Ledger + 안정된 Live JSONL에 기록
→ Wazuh localfile(JSON)
→ Custom Rule·Dashboard
→ Shuffle observe-only Gate
```

AWS 쪽은 Event가 생길 때 Queue로 밀어 넣고, 노트북은 48개 Log Stream을 반복 조회하지
않고 **서울·버지니아 Queue 두 개만 Long Poll**한다. 따라서 완전한 인터넷 Inbound Push가
아니라, `AWS Event-driven Push + 로컬 Queue Long Poll` 구조다.

여기서 Push의 조건과 탐지 조건을 구분한다.

```text
전달 조건: 승인된 Log Group·Region·S3 Prefix인가
탐지 조건: 그 Event가 위험한가 → Wazuh Rule이 판단
```

CloudWatch Logs Subscription의 Filter Pattern은 지정 Log Group의 **전체 Event를
Lambda로 전달**한다. `command.execution`·`GetObject` 같은 위험 조건은 Subscription에
넣지 않고 Wazuh Rule이 판정한다. 다만 SQS·노트북에 민감 원문을 복제하지 않도록 Lambda는
승인된 감사 필드만 `payload`에 남기며, 전체 원문 조사·재분석은 기존 CloudWatch Logs·S3
Archive와 10분 Poll이 담당한다.

## 2. 왜 다시 설계했는가

### 2.1 확인된 As-built

현재 Wazuh 4.14.7 AWS Wodle은 다음을 10분마다 직접 읽는다.

| 입력 | 현재 방식 | Region |
|---|---|---|
| CloudFront | CloudWatch Logs `GetLogEvents` | `us-east-1` |
| WAF | CloudWatch Logs `GetLogEvents` | `us-east-1` |
| DVWA | CloudWatch Logs `GetLogEvents` | `ap-northeast-2` |
| CloudTrail | Security Log S3 List/Get | `ap-northeast-2` 분석 범위 |
| ALB | Security Log S3 List/Get | `ap-northeast-2` |

CloudWatch 입력 상태 DB에서 추적 중인 Log Stream은 48개였다. 전역 주기를 1분으로
줄이면 새 Event가 없어도 최소 다음 호출 구조가 된다.

```text
48 GetLogEvents / minute
≈ 69,120 / day
≈ 2,073,600 / 30 days
+ Log Group별 DescribeLogStreams
+ CloudTrail·ALB S3 List
```

이는 최소 호출량 추정이며 청구액 계산이 아니다. 그러나 10분 대비 약 10배의 반복 조회와
로컬 처리 부하가 생기므로, `1m Poll`을 영구 Target으로 채택하지 않는다. Host와 Container
원본 설정은 `10m`으로 복구했다.

### 2.2 지연을 두 구간으로 나눈다

```text
사건 발생 → AWS 원본 로그 도착 → Wazuh 도착·Rule 평가
          [Source 고유 지연]     [우리 전달 지연]
```

Push 전환이 줄이는 것은 두 번째 구간이다. ALB·CloudTrail·CloudFront의 원본 생성·전달
지연까지 없애지는 못한다. 따라서 모든 Source에 같은 60초 목표를 강요하지 않는다.

## 3. Source별 역할과 목표 속도

| Source | 사건에서의 역할 | Target 입력 | 속도 판정 |
|---|---|---|---|
| DVWA 안전 Audit | IMDS 대상 Command 실행 시도 | 서울 CWL Subscription → Lambda → SQS | 최초 의심의 주 Trigger. Stretch 60초, 완료 기준 180초 이내 |
| WAF | Edge 요청 검사·Action·Label | 버지니아 CWL Subscription → Lambda → SQS | 빠른 보조 신호. AWS Log 수신 뒤 전달 지연 측정 |
| CloudTrail | Node Role의 STS·S3 API 사용 | 서울 CloudTrail CWL Subscription → Lambda → SQS | 침해 확인. 원본 CloudTrail 지연과 Queue 이후 지연을 분리 측정 |
| ALB | 요청이 Target까지 간 경로 | 서울 S3 ObjectCreated → SQS, Bridge가 Object Read | 경로 복원 Evidence. 실시간 Trigger로 사용하지 않음 |
| CloudFront | CDN Edge 도달 | 버지니아 Hot-copy CWL Subscription → Lambda → SQS | 지연 가능한 보조 Evidence. 실시간 Trigger로 사용하지 않음 |

기존 `CloudTrail Metric Filter → Alarm → SNS`는 AWS Native 사람 알림 경로로 그대로
유지한다. Wazuh와 경쟁하는 중복 SIEM이 아니라, SIEM 장애 때도 남는 독립 탐지 출력이다.

## 4. 리전별 구조

### 4.1 `ap-northeast-2`

```text
DVWA Log Group ───────┐
CloudTrail Log Group ─┼→ wazuh-push-primary Lambda → wazuh-push-primary SQS → DLQ
ALB S3 ObjectCreated ────────────────────────→ wazuh-push-primary SQS
```

ALB 알림 메시지는 Object 위치만 전달한다. Local Bridge가 승인된 `alb/primary/` Object만
읽고 각 Access Log Record를 개별 Event로 변환한다.

### 4.2 `us-east-1`

```text
WAF Log Group ─────────┐
CloudFront Hot Log Group ─→ wazuh-push-edge Lambda → wazuh-push-edge SQS → DLQ
```

두 Queue를 두는 이유는 CloudWatch Logs Subscription과 S3 Event Destination의 Region
경계를 단순하게 지키고, 한 리전 장애가 다른 리전 소비를 막지 않게 하기 위해서다. Local
Bridge는 Queue마다 별도 Long Poll Worker를 둔다.

## 5. Local Bridge와 Wazuh 경계

Primary DVWA 현재 구성:

```text
tools/Start-WazuhPushShadowBridge.ps1
→ Primary Queue ReceiveMessage(WaitTimeSeconds=20)
→ 임시 STS Reader Role·Schema·source=dvwa 검증
→ 단일 Writer Lock
→ Host Event별 JSON Ledger + wazuh-push-live.jsonl Flush
→ 성공한 메시지만 DeleteMessage

Wazuh Manager
→ <localfile>
→ <log_format>json</log_format>
→ /var/ossec/wazuh-push/dvwa/wazuh-push-live.jsonl
```

노트북이 꺼지면 SQS가 Event를 보관한다. Bridge가 켜져 있고 Wazuh가 꺼졌다면 Host Spool이
보관한다. 메시지는 **Host Spool에 안전하게 기록된 뒤에만** Queue에서 삭제한다.

## 6. Event 계약

모든 Event는 최소한 다음 공통 필드를 가진 한 줄 JSON으로 정규화한다.

```json
{
  "schema_version": 1,
  "event_id": "source-specific-stable-id",
  "source": "dvwa|waf|cloudtrail|alb|cloudfront",
  "aws_region": "ap-northeast-2|us-east-1",
  "event_time": "RFC3339",
  "aws_ingested_at": "RFC3339|null",
  "aws_forwarded_at": "RFC3339",
  "bridge_received_at": "RFC3339",
  "transport": "push",
  "raw_message_sha256": "sha256",
  "payload": {}
}
```

Primary DVWA의 `payload`는 `event_type`, `result`, `route`, `request_id`, 요청 분류값과
승인된 `context`만 허용한다. 비정형 원문은 저장하지 않고 `normalized=false`만 남긴다.

중복 제거 Key:

- CloudWatch Logs: `owner + logGroup + logStream + logEvent.id`
- ALB S3: `bucket + object key + object version/eTag + record index/hash`
- Wazuh Alert: 정규화된 `event_id + rule.id`

CloudWatch Logs Subscription과 S3 Event Notification은 중복 전달될 수 있으므로 exactly-once를
가정하지 않는다. 현재 Bridge는 `event_id` SHA-256별 JSON Ledger를 임시 파일에 Flush한 뒤
원자적으로 이름을 바꾸며, 정상 재수신은 건너뛴다. 하지만 Live JSONL Flush 뒤 Ledger Rename
전에 프로세스가 비정상 종료되면 한 건이 중복될 수 있으므로 전달 보장은 at-least-once다.

## 7. 실패·재시도·복구 경계

| 실패 | 기대 동작 | 증거 |
|---|---|---|
| 노트북·Docker Off | SQS에 보존, 재기동 후 Catch-up | Queue age/depth 전후 |
| Bridge가 Spool 쓰기 실패 | 메시지 삭제 금지, Visibility Timeout 뒤 재시도 | Bridge error + Queue redelivery |
| Lambda 변환 실패 | 재시도 후 DLQ | Lambda error metric + DLQ message |
| 정상 재전달 | 유효한 Event Ledger가 두 번째 처리를 건너뜀 | 같은 `event_id` Ledger·Alert 확인 |
| JSONL Flush 직후 비정상 종료 | 유실 대신 재전달·중복 가능 | 장애 주입 Duplicate Test |
| 잘못된 Schema·과대 Payload | 본 Queue에서 제거하지 않고 격리 경로로 보냄 | quarantine/DLQ record |
| Push 경로 장애 | 해당 Source만 10m Poll 설정으로 수동 Rollback | Toggle·재수집 범위 기록 |

Polling과 Push를 같은 Source에 동시에 켜면 중복 Alert가 생길 수 있다. 전환은 Source별로
수행하고, Shadow 검증 파일과 Live Wazuh 입력을 구분한다.

## 8. 보안 경계

- Wazuh Dashboard나 노트북에 인터넷 Inbound Port를 열지 않는다.
- Subscription Filter는 승인된 Log Group에만 만들고, 해당 Group의 저장 Event 전체를
  전달한다. 위험 여부는 Forwarder가 아니라 Wazuh Rule이 판단한다.
- Forwarder Payload는 안전 필드 Allowlist이며, 임의 `message`·`log`, Credential, Cookie,
  Command 원문·응답을 저장하지 않는다. 원문 식별은 SHA-256만 남긴다.
- Forwarder Lambda의 자체 Log Group은 Subscription 대상에서 제외해 재귀 전송을 막는다.
- Lambda는 자기 리전 Queue의 `sqs:SendMessage`만 허용한다.
- S3 Bucket Notification은 `alb/primary/` Prefix의 `ObjectCreated`만 서울 Queue로 보낸다.
- 현재 Local Consumer는 Primary Queue의 `ReceiveMessage`, `DeleteMessage`,
  `GetQueueAttributes`만 임시 Reader Role로 사용한다. Edge Queue와 ALB `s3:GetObject`는
  P3 확장 때 별도 추가한다.
- Credential, Cookie, 원본 Command Response는 정규화 Payload와 영상에 남기지 않는다.
- Push Cutover 뒤 사용하지 않는 `logs:GetLogEvents`, `logs:DescribeLogStreams`, CloudTrail
  S3 Object Read 권한은 제거 후보로 표시한다.

## 9. 비용 경계

이 설계는 비용이 0이라는 뜻이 아니다. Lambda Invocation·실행 시간, SQS Request·보존,
CloudWatch Logs Subscription 전달과 ALB S3 Object Read가 사용량에 따라 발생한다.

첫 DVWA Shadow Plan에는 다음을 포함한다.

- `enable_wazuh_push_transport = false` 기본값
- 리소스 공통 Cost Allocation Tag
- Queue Retention 4일, DLQ Retention 14일의 명시적 값
- Lambda 128MB·30초, SQS Batch 10건 상한. 계정 동시성 Quota 때문에 Reserved Concurrency는
  설정하지 않고 실제 Error·Throttle을 관찰한다.
- Source·Region·ALB Prefix를 Allowlist로 제한하되, 선택한 Source 내부 Event는 탐지 조건으로
  잘라내지 않음
- Apply 전 월간 호출량 상·하한 계산과 Budget 확인

Lambda·SQS Error/Backlog Alarm은 **P2 Live Cutover 전** 추가한다. 현재 Primary DVWA
Resource와 Wazuh 전용 JSONL 입력은 적용됐지만, 기존 Poll을 끄지 않은 검증 단계이므로
Queue depth·DLQ·Lambda Error는 아직 수동 조회한다.

전 리전·전 Source를 한 번에 켜지 않는다. DVWA 한 Source의 실제 Event량과 비용을 측정한
뒤 WAF → CloudTrail → ALB → CloudFront 순으로 확장한다.

## 10. 단계별 전환 Gate

### P0 — 설계·정적 계약

- [x] 기존 1분 Poll 실험을 종료하고 10분 원본·Runtime 복구
- [x] 5개 Source·Region·보존 위치 대조
- [x] Event Schema, IAM, Queue/DLQ, Lifecycle을 정적 Test로 고정
- [x] Terraform Plan에서 기본 Toggle Off의 AWS Resource 0-change 확인
  - 새 비민감 Output만 State에 추가될 예정이며 실제 AWS Resource 변경은 0개

### P1 — DVWA Shadow Transport

- [x] 서울 Lambda·Queue·DLQ·Subscription의 비파괴 Saved Plan 확인
  - `9 add / 1 in-place update / 0 destroy`
  - 갱신 1개는 기존 Wazuh Reader Role에 Primary Queue Receive/Delete 권한 추가
- [x] 명시적 승인 뒤 Saved Plan Apply
- [x] 안전 Payload Allowlist 보강 Lambda Apply: `0 add / 1 update / 0 destroy`
- [x] 동일 활성 입력 Post-Apply Plan `No changes`
- [x] DVWA Log Group 전체 Event Subscription → Queue → Event Ledger·Live JSONL 연결
- [x] 실제 무해 Event 3회에서 누락 0, Rule `100102` 3건 확인
- [x] `event_time → Wazuh Alert` 지연 6.439초·3.427초·3.761초
- [ ] 월간 실제 사용량·비용 측정

| Take | Event→Forwarder | Forwarder→Bridge | Bridge→Wazuh Alert | 총 지연 |
|---|---:|---:|---:|---:|
| `wazuh-push-20260817T102046747Z` | 3.134초 | 2.207초 | 1.098초 | **6.439초** |
| `wazuh-push-20260817T102127824Z` | 2.426초 | 0.240초 | 0.761초 | **3.427초** |
| `wazuh-push-20260817T102209527Z` | 2.381초 | 0.242초 | 1.138초 | **3.761초** |

세 검증 Event는 공격이 아닌 `SAFE_VALIDATION_EVENT`이며 `payload.normalized=true`와
Rule `100102`를 확인했다. 최대 6.439초·중앙값 3.761초로 60초 Stretch 목표를 통과했다.
Bridge 종료 뒤 Primary Queue의 Visible·In-flight·Delayed와 DLQ의 동일 세 값은 모두 `0`이었다.
세 Take ID는 Live JSONL과 `alerts.json`에서 각각 정확히 1건씩이었다. 이는 정상 실행의
중복 0 증거이며, 위의 비정상 종료 Crash Window 검증을 대신하지 않는다.

### P2 — DVWA Live Cutover

- [x] 안정된 Live JSONL을 Wazuh `localfile(json)` 전용 검증 입력으로 연결
- [ ] 실제 `command.execution`을 Push Rule `100103`으로 3회 검증
- [ ] DVWA Poll 입력만 비활성화해 이중 수집 방지
- [ ] Poll Rule `100101`과 Push Rule `100103`의 Cutover 의미 확정
- [ ] Docker Off/On Catch-up과 Duplicate Test 통과

### P3 — 나머지 Source 확장

- [ ] WAF → CloudTrail → ALB → CloudFront 순서로 한 Source씩 전환
- [ ] Source마다 Raw Field·Dashboard·Rule 호환 확인 후 Poll 비활성화
- [ ] CloudTrail Rule `100100`의 기존 의미 조건 유지

### P4 — 운영 경계 마감

- [ ] 5개 Source의 Push·Archive·Fallback 상태표 확정
- [ ] 사용하지 않는 Reader 권한 축소
- [ ] Queue·DLQ·Lambda 지표와 Runbook 완성
- [ ] 기존 10분 Poll은 동시 실행이 아닌 수동 Rollback 경로로 보존

### P5 — SOAR 연결

- [ ] Wazuh Alert → Shuffle Dry Run
- [ ] `event_id` 기준 중복 대응 차단
- [ ] Rule `100103` 실제 Runtime Gate 통과 뒤에만 v2 대응 계약으로 이동
- [ ] Workload/IAM Containment와 GitOps Remediation을 별도 Gate·Workflow로 유지

## 11. 구현 소유권

| 영역 | 위치 | 이유 |
|---|---|---|
| Queue·DLQ·Lambda·Subscription·S3 Notification·IAM | `foundation/` Terraform | 현재는 DVWA만 구현. 원본 Log Group·S3와 함께 Daily Runtime 밖에서 지속 |
| CloudFront Lab Hot-copy Delivery | Root Daily Terraform | 현재 `capital-one-lab`에서만 생성 |
| Local Bridge·Spool·Ledger | `tools/Start-WazuhPushShadowBridge.ps1` + 로컬 비밀 제외 설정 | Event ID별 원자 Ledger와 안정 Live JSONL. 단일 Writer·임시 STS Session 사용 |
| Wazuh localfile·Rule | `D:/Wazuh/wazuh-docker/single-node/config/` | Host-mounted 영구 원본 |
| Dashboard·Saved Object | Local Wazuh Indexer + Export Artifact | Terraform 관리 대상 아님 |

## 12. 완료 정의

다음이 모두 있어야 “Push 전환 완료”라고 말한다.

- 같은 고유 Event의 `event_time`, AWS Forward, Bridge 수신, Wazuh Alert 시각
- 실제 Event 3회 누락 0과 Wazuh/Shuffle 중복 0
- 노트북 10분 Off 뒤 Queue Catch-up 성공
- DLQ 강제 실패와 재처리 성공
- Default Toggle Off Plan 0-change와 승인된 Source별 Apply
- Push 장애 시 Source 하나만 10분 Poll로 되돌리는 Runbook
- S3·CloudWatch 원본 Archive가 Push와 무관하게 계속 보존됨

## 13. 공식 근거

- [CloudWatch Logs 실시간 Subscription](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Subscriptions.html)
- [CloudWatch Logs Subscription Filter](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/SubscriptionFilters.html)
- [CloudWatch Logs 재귀 전송 방지](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Subscriptions-recursion-prevention.html)
- [S3 Event Notification Destination·중복 전달](https://docs.aws.amazon.com/AmazonS3/latest/userguide/notification-how-to-event-types-and-destinations.html)
- [SQS Long Polling](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/best-practices-setting-up-long-polling.html)
- [Wazuh `localfile` JSON 입력](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html)

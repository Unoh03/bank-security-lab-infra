# Capital One 기반 SOC 시연 활성 계획 v2

> **상태:** ACTIVE PLAN — Event·Rule·Timeline Dashboard Runtime 검증 완료, 자동 행동 미연결
>
> **기준점:** `4ec4b8e3ac1e44f8c2dd4dd39aef4c73d891f20b`
>
> 기존 `GT-00~GT-11` 장문 계획과 Rule `100103/100104`의 과거 의미는 위 Git 이력에
> 보존한다. 이 문서는 지금부터 사용할 단일 활성 계획이다.

---

## 1. 시연이 증명할 것

이 시연은 다음 한 문장을 실제 Runtime Evidence로 증명한다.

> **DVWA를 통한 IMDS Credential 접근을 저지연으로 탐지해 Workload를 자동 격리하고,
> 뒤이어 보호 S3 Object 접근 성공을 별도 Rule로 확정해 애플리케이션을 자동으로
> `low → impossible`로 변경한 뒤, 관제자가 전체 Timeline을 조사해 WAF에 좁은 차단을
> 적용하고 같은 공격 Payload가 Edge에서 차단되어 조기탐지 Event조차 다시 발생하지
> 않음을 정상 대조군과 함께 확인한다.**

영상의 주인공은 공격 도구가 아니라 다음 관제 흐름이다.

```text
탐지
→ 자동 긴급 대응
→ 침해 확인과 자동 애플리케이션 완화
→ 사람의 사건 조사
→ 사람 승인 Edge 차단
→ 재공격과 정상 대조군
```

---

## 2. 주장 범위

- 실제 Capital One 사고의 SSRF를 그대로 재현하지 않는다.
- 교육용 DVWA Command Injection을 최초 진입점으로 사용한다.
- 공격 대상은 승인된 Lab의 고정 가짜 Object
  `validation/capital-one-demo.csv`로 제한한다.
- Credential 원문, Session Token, Cookie, Webhook Secret, PAT, 공격 응답 본문은
  로그·Evidence·영상에 저장하지 않는다.
- `GetObject` 성공은 고정 가짜 Object 읽기 성공이다. 대규모 외부 반출 전체를
  증명했다고 표현하지 않는다.
- `low → impossible`은 DVWA 애플리케이션 완화다. 이미 발급된 AWS Credential을
  폐기하거나 Node Role 권한을 제거하는 조치라고 표현하지 않는다.
- WAF 차단은 최초 HTTP 진입점의 가상 패치·추가 방어다. 애플리케이션 Root Cause 자체를
  수정했다고 표현하지 않는다.
- Source 존재, Rule Source, 정적 Test, 과거 Runtime, 현재 Runtime을 구분한다.

---

## 3. 고정 시나리오

| 상태 | 발생·행동 | 반드시 남길 Evidence |
|---|---|---|
| `S0 READY` | Wazuh·Push Bridge·Dashboard·대응 경로 정상 | READY 시각, Health Event |
| `S1 ENTRY` | WAF가 `POST /vulnerabilities/exec/`을 검사하지만 최초 공격은 `COUNT/ALLOW` | WAF Action·Label·Request 시각 |
| `S2 CREDENTIAL RISK` | DVWA가 IMDS Credential endpoint 대상 명령의 출력 반환을 Audit | 안전한 Stage, Push `event_id` |
| `S3 AUTO ISOLATION` | Rule `100110`이 발생하고 고정 DVWA Workload를 자동 격리 | Alert ID, Execution ID, Policy UID/Revision, 실제 격리 효과 |
| `S4 S3 CONFIRMED` | 이미 획득된 임시 Credential로 고정 S3 Object 읽기 성공 후 CloudTrail 도착 | CloudTrail `eventID`, Principal, Object, 성공 상태 |
| `S5 AUTO HARDENING` | Rule `100111`이 발생해 자동 `low → impossible` | Execution ID, Commit SHA, Argo Revision, 새 Pod 상태 |
| `S6 INVESTIGATION` | 사람이 Incident Timeline Dashboard에서 진입부터 대응까지 설명 | 동일 시간창의 WAF·DVWA·Rule·CloudTrail·대응 |
| `S7 WAF MITIGATION` | 사람이 좁은 WAF 차단을 승인·적용 | Rule Diff, 적용 시각, WAF Read-back |
| `S8 REATTACK` | 같은 공격 Payload를 다시 보내 WAF `BLOCK/403` 확인 | WAF terminating Rule, downstream 0 |
| `S9 CLOSE` | 정상 기능과 탐지 파이프라인 Health를 확인 | 정상 요청 성공, Health Event 성공, 신규 공격 Alert 0 |

### 순서 불변조건

- Rule `100110`은 역할 이름 조회가 아니라 **Credential endpoint 조회 단계**에서만 발생한다.
- 자동 Workload 격리는 두 번째 IMDS 요청 뒤 시작하므로 최초 TAKE의 Credential 획득
  단계와 충돌하지 않는다.
- 고정 S3 읽기는 공격 Runner가 메모리에 보관한 짧은 수명의 임시 Credential로 수행한다.
  따라서 DVWA Workload 격리 뒤에도 이미 시작된 S3 접근 Evidence가 도착할 수 있다.
- Rule `100111`과 CloudTrail은 전송 지연이 있을 수 있으므로 실제 Event 시각과
  Wazuh Alert 시각을 별도로 표시한다.
- 재공격 성공 판정은 Alert 0 하나로 하지 않는다. WAF `BLOCK`과 downstream 0,
  정상 요청 성공, 탐지 Health 성공을 함께 요구한다.

---

## 4. Rule v2 계약

### 4.1 Legacy·Retired Rule

| Rule | 보존 이유 | 활성 자동화 |
|---|---|---|
| `100103` | 일반 IMDS 대상 Push 탐지와 과거 Dashboard 보존 | 없음 |
| `100100` | 이전 보호 Object 탐지 계약은 Git 이력에만 보존하고 활성 Rule에서 폐기 | 없음 |
| `100104/100105/100109` | 이전 Push·S3 탐지 계약은 Git 이력에만 보존하고 활성 Rule에서 폐기 | 없음 |

신규 Workflow·Dashboard의 자동화 후보는 `100110/100111`만 사용한다. `100103`은 일반
IMDS 관측용으로 남고, `100100/100104/100105/100109`는 활성 Rule에 없다.

### 4.2 Rule `100110` — Credential 접근 조기탐지

#### Source Event 계약

DVWA Audit는 원문 Command·URL·Role 이름·응답·Credential을 저장하지 않고 다음 안전
분류값만 추가한다.

```text
context.stage = imds_role_discovery | imds_credential_fetch | other
```

- `/latest/meta-data/iam/security-credentials/` 조회는 `imds_role_discovery`다.
- 그 아래 한 Role의 Credential endpoint 조회는 `imds_credential_fetch`다.
- 분류는 서버 측 Audit 함수가 요청 Target을 검사해 생성한다.
- Client가 보낸 Stage Header나 자유 문자열을 신뢰해 Rule을 발생시키지 않는다.

#### Match 계약

```text
transport=push
source=dvwa
payload.event_type=command.execution
payload.result=succeeded
payload.route=/vulnerabilities/exec/
payload.context.action=shell_command
payload.context.resource=ec2_imds
payload.context.security_level=low
payload.context.stage=imds_credential_fetch
payload.context.status=output_returned
```

Rule Level은 `12`로 고정한다. Rule Description은 Credential 원문 획득을 확정했다고
과장하지 않고 다음 의미를 전달한다.

> `AWS-SOC: DVWA command returned output from the EC2 IMDS credential endpoint.`

#### 자동 행동

```text
Rule 100110
→ 인증·Schema·Allowlist 검증
→ Push event_id Dedupe
→ 고정 Namespace/Workload의 DVWA Quarantine
```

격리는 고정 DVWA Workload만 대상으로 하는 사전 승인 정책이다. Rule Payload 값으로
Namespace, Deployment, Repository, Branch, Command를 선택하지 않는다.

격리 성공은 Resource 생성만으로 판정하지 않는다.

- 정책 UID/Revision이 Read-back된다.
- DVWA Workload의 금지된 Egress가 실제 실패한다.
- 관측·Health에 필요한 고정 경로는 유지된다.
- 다른 Namespace와 비대상 Workload 영향은 0이다.
- 동일 Push `event_id` 재전달 시 실제 조치는 총 1회다.

### 4.3 Rule `100111` — S3 침해확정 직접 탐지 Rule

#### 현재 Event 조건

```text
CloudTrail
eventSource=s3.amazonaws.com
eventName=GetObject
eventType=AwsApiCall
eventCategory=Data
managementEvent=false
readOnly=true
recipientAccountId=<승인 Account exact>
awsRegion=ap-northeast-2
userIdentity.type=AssumedRole
sessionIssuer.userName=<고정 Primary Node Role exact>
bucketName=aws-topology-primary-<26 hex>
key=validation/capital-one-demo.csv
httpStatusCode=200
bytesTransferredOut>0
eventID=UUID
```

#### 판정·조사 경계

- Rule `100111`은 위 고정 Account·Region·Role·Bucket·Object의 실제 바이트 반환 성공을
  CloudTrail 원본 Event만으로 직접 판정한다.
- 성공 Event에는 일반적으로 `errorCode`가 없지만, 선택 필드의 부재를 Wazuh Rule 조건으로
  요구하지 않는다. 성공 판정은 `httpStatusCode=200`과 `bytesTransferredOut>0`으로 고정한다.
- Rule `100110`과 `100111`은 서로 독립적으로 발생한다. Wazuh의 선행 Rule 기반 네이티브
  시간창 상관을 사용하거나 주장하지 않는다.
- 관제자는 Timeline에서 Event 시각, Push `take_id/event_id`, CloudTrail `eventID`를 함께
  보고 두 탐지가 같은 공격 흐름인지 조사한다.
- 자동 행동 Validator는 고정 Target Allowlist, 입력 Schema, Event Dedupe, 실패 처리를
  검증해야 한다. 이 경로는 `P2.5` 조사 전에는 구현하지 않는다.

Rule Level은 `14`로 고정한다. Description은 다음 의미로 제한한다.

> `CAPITAL-ONE: Protected S3 object bytes were returned through the compromised node role.`

#### 자동 행동

```text
Rule 100111
→ CloudTrail eventID Dedupe
→ 고정 GitHub Workflow/Repository/Branch
→ DEFAULT_SECURITY_LEVEL: low → impossible
→ Argo CD exact revision 배포
```

- 사람 승인을 기다리지 않는 사전 승인 자동 대응이다.
- 변경 대상은 고정 DVWA 보안 설정 하나다.
- 동일 CloudTrail `eventID` 재수집 시 GitHub Commit·Argo Rollout은 총 1회다.
- 예상하지 않은 Diff, Branch, Repository, 보안 수준이면 실행을 거부한다.
- 성공은 GitHub Run, Commit SHA, Argo exact Revision, 새 Pod, 새 Session의
  `security=impossible` Read-back으로 판정한다.

---

## 5. 사람의 조사와 WAF 조치

### 5.1 Incident Timeline Dashboard

`SOC 실시간 보안관제`의 Push 표만으로 전체 인과관계를 설명했다고 주장하지 않는다.
별도 `Capital One Incident Timeline v2` Dashboard를 만들었고, `100110/100111` Fresh Runtime과
각 Source 근거가 실제 화면에 표시되는 것을 2026-08-21 확인했다.

최소 표시 항목:

- WAF `COUNT/ALLOW`, Managed Label, Method, Path
- DVWA `stage=imds_role_discovery`
- DVWA `stage=imds_credential_fetch`
- Rule `100110`과 자동 Quarantine 결과
- CloudTrail `GetObject`와 Rule `100111`
- 자동 `low → impossible` Execution·Commit·Argo Revision
- 사람의 WAF 조치 시각
- 재공격 WAF `BLOCK`
- downstream 신규 Event 0과 정상/Health 대조군

Dashboard는 자동 인과 추론을 주장하지 않는다. 고정 시간창·Rule ID·`event_id`·
CloudTrail `eventID`·Execution ID로 사건을 좁혀 보여준다.

### 5.2 WAF 조치 계약

관제자는 Dashboard에서 최초 악성 HTTP 진입점을 확인한 뒤 사전 준비된 좁은 WAF 변경을
검토하고 사람 승인으로 적용한다.

```text
AWS Managed Common Rule의 EC2MetaDataSSRF_Body Label
AND Method=POST
AND URI=/vulnerabilities/exec/
→ BLOCK
```

- 전체 `AWSManagedRulesCommonRuleSet`을 일괄 BLOCK으로 바꾸지 않는다.
- Source IP 하나에 영구 의존하지 않는다.
- 정상 Numeric IP Ping은 차단하지 않는다.
- Console 임시 수정이 아니라 재현·Rollback 가능한 IaC/Runbook 경로를 사용한다.
- 적용 완료는 WAF Rule Read-back과 새 요청의 terminating Rule로 확인한다.

---

## 6. 재공격 계약

기존 Baseline Runner는 DVWA가 `low`가 아니면 공격 전에 중단하므로 최종 재공격 증명에
그대로 사용하지 않는다. 동일 Payload를 전송하는 전용 Reattack Runner를 사용한다.

### 공격 대조

- 현재 DVWA가 `impossible`이어도 CSRF Token을 획득한다.
- 최초 공격과 같은 IMDS role-discovery Payload를 `POST /vulnerabilities/exec/`로 보낸다.
- 새 `REATTACK_ID`와 시작 UTC를 기록한다.
- HTTP `403` 하나만으로 WAF 차단을 확정하지 않는다.

### PASS

```text
WAF action=BLOCK
WAF terminating rule=<사람이 적용한 고정 Rule>
HTTP status=403
ALB 신규 공격 요청=0
DVWA 신규 command.execution=0
Push 신규 공격 Event=0
Rule 100110 신규 Alert=0
CloudTrail 보호 Object 신규 GetObject=0
Rule 100111 신규 Alert=0
추가 자동 대응=0
```

### 정상·Health 대조

- 정상 로그인·홈 화면이 성공한다.
- 안전한 Numeric IP Ping이 성공한다.
- 별도 Push Health Event가 Wazuh에 도착한다.
- 따라서 Alert 0의 원인이 WAF 선차단이지 수집 장애가 아님을 증명한다.

---

## 7. 실행 단계

### `P1` — 문서·계약

- 이 계획과 녹화 대본을 동일 Rule·행동·장면으로 고정한다.
- Legacy Rule과 v2 Rule의 의미를 분리한다.

### `P2` — Event·Rule

- 완료: DVWA 안전 Stage 분류와 실제 Push 전달
- 완료: Push Forwarder `stage` Allowlist 배포와 실제 Event 확인
- 완료: Rule `100110` Source, Positive·Negative·중복 Matrix, Fresh Runtime
- 완료: Rule `100111` 직접 탐지 Source, Positive 1·Negative 15·중복 0 Matrix
- 완료: Fresh CloudTrail의 예약 10분 수집 후 Rule `100111` Runtime 확인
- 완료: Wazuh `analysisd -t`와 `wazuh-logtest`

### `P2.5` — 자동 대응 경로 사전 학습

`P3`에 진입하기 전에 다음 질문을 해소하기 위한 조사·학습을 먼저 수행한다.

> 현재 저장소와 실제 제품 기능만으로 `100110 → 고정 DVWA 격리`,
> `100111 → 고정 low→impossible`을 안전하고 재현 가능하게 만들 수 있는가?
> 가능하다면 최소 연결 경로·필요 권한·실패 처리·검증 증거는 정확히 무엇인가?

이 단계에서는 구현·Workflow 배포·실제 자동 행동을 수행하지 않는다. 조사 결과로 가능한
최소 경로를 정한 뒤에만 `P3`에 진입한다.

### `P3` — 자동 대응

- `100110 → fixed DVWA Quarantine`
- `100111 → low→impossible`
- 각 Dedupe와 실패 상태
- 실제 Runtime Read-back과 Blast Radius

### `P4` — 조사 화면·WAF·재공격 Runner

- `Capital One Incident Timeline v2` NDJSON Source와 Live Dashboard 구성 완료
- Rule `100110/100111` Fresh Runtime과 각 Source 근거의 실제 화면 표시 확인 완료
- 자동 행동은 아직 연결되지 않아 대응 결과 필드는 `NOT CONNECTED` 상태로 유지
- 좁은 WAF 변경과 Rollback 계약
- 같은 Payload Reattack Runner

### `P5` — Fresh E2E

- 새 TAKE 한 번으로 `S0~S5` 실제 실행
- 사람이 Dashboard를 조사하고 WAF 적용
- 새 REATTACK으로 `S8~S9` 검증
- 실패하면 같은 TAKE의 일부 단계만 재사용하지 않고 원인을 수정한 뒤 새 TAKE를 사용

### `P6` — Rehearsal·Recording

- 다른 팀원이 Dashboard만 보고 3분 안에 흐름과 조치를 설명
- 전체 장면 2회 무중단 Rehearsal
- Secret-safe 최종 촬영

---

## 8. 현재 상태 — 2026-08-21

| 항목 | 현재 판정 |
|---|---|
| 기존 공격 Runner로 IMDS Credential·고정 가짜 S3 읽기 | Runtime 확인 |
| DVWA Image→Pod 동일 Digest와 Stage Source | Runtime 확인 |
| Push Lambda `stage` 전달 | 2026-08-21 Targeted 배포 후 Runtime 확인 |
| Push Bridge와 `imds_role_discovery/imds_credential_fetch` | Fresh Runtime 확인 |
| Rule `100110` Level 12 | Matrix PASS, Fresh Runtime PASS |
| Rule `100111` Level 14 직접 탐지 | Matrix PASS, Fresh 예약 수집 Runtime PASS |
| Rule `100100/100104/100105/100109` | 활성 Rule에서 폐기, Git 이력만 보존 |
| `100110` 실제 자동 Workload 격리 | 미검증 |
| `100111 → low → impossible` 자동 연결 | 미구현·`P2.5` 조사 전 동결 |
| 전체 Incident Timeline Dashboard | Source·Live Runtime PASS, 자동 행동은 `NOT CONNECTED` |
| 사람 승인 WAF 차단 | 미구현 |
| WAF 전용 Reattack Runtime | 미검증 |

Fresh Runtime 기준은 TAKE `capital-one-20260821T070639Z-5d32099e`다. 공격은
`2026-08-21T07:06:54.0828064Z`에 시작해 `07:07:04.8869155Z`에 끝났고, Rule `100110`은
`16:07:10.092+09:00`에 발생했다. 고정 Object `GetObject`의 CloudTrail `eventID`는
`069248dc-333f-4925-a8af-4f92f2e4e977`, Event 시각은 `07:07:05Z`이며, 다음 예약 수집 뒤
Rule `100111`이 `16:15:27.187+09:00`에 발생했다. Dashboard에서 두 Alert와 각 Source 근거를
같은 시간창에 표시했다. 과거 Source·Test·Runtime Evidence를 이 완료 증거로 대체하지 않는다.

---

## 9. 시연 시작조건

아래가 모두 실제 Runtime으로 확인되기 전에는 녹화 대본을 실행하지 않는다.

- Rule `100110` Positive와 모든 Negative Control
- Rule `100111` Positive·Negative Control·중복 0
- 자동 Quarantine 1회와 실제 효과
- 자동 `low → impossible` 1회와 실제 배포
- 중복 Event 재전달 시 추가 조치 0
- Timeline Dashboard에서 한 Incident 설명 가능
- 사람 승인 WAF 적용과 Read-back
- 동일 Payload WAF 차단과 downstream 0
- 정상 기능과 Push Health 성공
- Secret 노출 0

Evidence는 TAKE별 핵심 ID·UTC·Outcome을 담은 단일 Sanitized Summary와 촬영용 화면만
보존한다. 작은 검증마다 새 Gate·Bundle을 만들지 않는다.

---

## 10. 금지 표현

```text
Rule 100110이 Credential 원문 탈취를 직접 증명했다.
Rule 100111 단독으로 DVWA가 원인임을 증명했다.
S3 API 호출 순간 Wazuh가 즉시 격리했다.
low → impossible이 기존 AWS Credential을 폐기했다.
WAF가 애플리케이션 Root Cause를 수정했다.
Alert가 0이므로 WAF 차단이 증명됐다.
Dashboard가 자동으로 공격 인과관계를 추론했다.
```

정확한 표현:

```text
Rule 100110은 DVWA의 IMDS Credential endpoint 대상 명령 출력 반환을 조기에 탐지했다.
Rule 100111은 고정 S3 Object의 실제 바이트 반환 성공을 직접 탐지했고, 관제자는 Timeline에서
앞선 Rule 100110과 같은 공격 흐름으로 조사했다.
사전 승인된 두 자동 대응은 각각 Workload 격리와 DVWA low→impossible을 수행했다.
관제자는 Timeline을 조사해 좁은 WAF 차단을 승인했다.
재공격은 WAF에서 차단됐고 downstream 0, 정상 기능, 수집 Health를 함께 확인했다.
```

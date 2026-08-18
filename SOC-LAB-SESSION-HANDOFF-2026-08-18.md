# SOC Lab 세션 인수인계 — 2026-08-18

> 상태: **HISTORICAL SESSION RECORD / 현재 실행 기준 아님**
>
> 기준 시각: 2026-08-18 11:56 KST
>
> 이 문서는 2026-08-18 오전의 조사·실패 기록을 보존한다. 현재 대응 정본은
> [`CAPITAL-ONE-INCIDENT-RESPONSE-SCENARIO.md`](./CAPITAL-ONE-INCIDENT-RESPONSE-SCENARIO.md),
> 현재 실행 순서는 [`CAPITAL-ONE-SOC-DEMO-PLAN.md`](./CAPITAL-ONE-SOC-DEMO-PLAN.md),
> 상세 Target은 [`CAPITAL-ONE-SOC-E2E-BLUEPRINT.md`](./CAPITAL-ONE-SOC-E2E-BLUEPRINT.md)다.
> 아래의 당시 `현재` 표현과 v1 Workflow 이름을 오늘의 Runtime Truth로 읽지 않는다.

> **현재 재개점:** `low → impossible`은 Remediation이며, Workload Quarantine과 제한된
> IAM 영향 차단이 Containment다. 실제 `command.execution → Wazuh Rule 100103` 저지연
> 경로를 먼저 닫고, 그 전에는 downstream 대응을 구현하지 않는다.

## 0. 다음 세션은 여기서 시작한다

다음 세션의 첫 행동은 구현이 아니다.

1. 대응 정본과 Demo Plan의 `지금 바로 할 한 가지`를 읽는다.
2. `git status --short`로 Terraform과 DVWA의 현재 변경을 확인한다.
3. AWS Daily Runtime과 Watchdog는 현재 State에서 다시 확인한다.
4. 실제 AWS `command.execution → Rule 100103` 3 TAKE를 `observe_only`로 검증한다.
5. Offline Catch-up·DLQ·DVWA Poll Rollback을 확인한다.
6. 그 전에는 v2 Production Dispatch·NetworkPolicy·IAM·Remediation·Reset을 진행하지 않는다.

아래 상태는 계획서 문구가 아니라 2026-08-18에 다시 확인한 Source·Runtime 기준이다.

---

## 1. 사용자가 실제로 만들고 싶은 것

### 1.1 최종 사용자 장면

```text
노트북에서 SOC 시작 명령 1회
→ 시연에 필요한 Wazuh와 로컬 구성요소 READY
→ DVWA Command Injection 기반 Capital One 각색 공격
→ Rule 100103 저지연 탐지
→ 정제된 Alert만 Shuffle 전달
→ 동일 TAKE의 중복 대응 차단
→ DVWA Workload Quarantine과 허용된 IAM 영향 차단
→ 느린 5-Source Evidence로 Incident 조사·확인
→ values.yaml의 low → impossible 보안 설정 Remediation
→ Argo CD가 각 정확한 Commit을 EKS에 배포
→ 격리/패치 효과를 분리한 공격 실패·정상 기능 확인
→ 별도 수동 Reset에서 Quarantine을 마지막에 해제
```

### 1.2 이것이 의미하지 않는 것

- 모르는 공격을 AI가 완벽히 해석하고 임의의 치료 코드를 작성하는 범용 SOC가 아니다.
- `low → impossible`은 DVWA 전용 **애플리케이션 보안 설정 Remediation**이다.
- Containment는 Workload Quarantine과 허용된 IAM 영향 차단이며 공유 Role 전체 자동 Deny는 금지한다.
- `TAKE_ID`는 시연 실행을 묶는 교육용 사건 키다. 실무 원칙은 특정 이름이 아니라
  안정적인 Correlation Key와 Idempotency다.
- 노트북이 꺼진 동안 24시간 탐지하는 것이 이번 프로젝트 완료 조건은 아니다.
- Local Wazuh를 기업의 Production 배치와 같다고 주장하지 않는다.

### 1.3 사용자의 현재 요구

- “현재 만든 것을 관성적으로 정당화”하지 말 것.
- 4번류 지식만으로 판단하지 말고, 로컬 Runtime·Source → 공식 문서·표준 → 공개 실무
  사례 순서로 근거를 대조할 것.
- 실행 전에 무엇을 왜 하는지 설명하고, 사용자가 흐름을 이해한 뒤 진행할 것.
- Source 존재, 과거 Evidence, 현재 Runtime, 목표 설계를 절대 섞지 말 것.
- 정적 Test나 파일 존재를 E2E 완료로 부르지 말 것.
- `ㄱㄱ`는 바로 직전에 합의한 좁은 범위만 승인한다.

---

## 2. 11:56 KST 당시 As-built 상태 — Historical

## 2.1 AWS Daily Runtime — 당시 활성

확인된 상태:

- Session: `20260818T015429Z-08b56734`
- `RuntimeProfile`: `minimal`
- `SecurityScenarioProfile`: `capital-one-lab`
- `WatchdogMode`: `Off`
- 최초 Apply: `124 added, 0 changed, 0 destroyed`
- wrapper 수정 후 재실행: Terraform `0/0/0`, 최종 exit `0`
- Terraform state: 165 addresses
- EKS Cluster와 Node Group: `ACTIVE`
- Argo CD: `Synced / Healthy`
- 배포 Revision: `0997d2a...`
- DVWA: wrapper 내부 Ready·HTTP 확인 성공, 이후 사용자도 접속 성공을 확인함

주의:

- 이 Runtime은 비용이 발생한다.
- Watchdog가 꺼져 있으므로 세션을 끝낼 때 수동 `daily-down`이 필요하다.
- 마지막 별도 `Invoke-WebRequest` 재확인은 실패했지만, 직전 wrapper와 사용자 브라우저
  확인은 성공했다. 이 둘을 숨기지 말고 충돌하는 Evidence로 보존한다.

## 2.2 Terraform Git 상태 — 당시 미커밋 2개

현재 `D:\terraform\aws_terraform_build_code`:

```text
 M daily-up.ps1
 M tools/Install-ShuffleSocAppBundle.ps1
```

변경 의미:

1. `daily-up.ps1`
   - `Assert-CommandAvailable`, `gh`, `Sync-ApplicationRepository`의 성공 출력이 PowerShell
     Success Stream에 섞여 `$image`가 배열이 된 문제를 막았다.
   - 원래 오류: `The property 'Repository' cannot be found on this object.`
   - 수정 뒤 Parser, wrapper guard, GitOps 검증과 실제 no-op 재실행이 통과했다.
   - 이 수정은 보존하되 다음 세션에서 Diff를 독립 검토한 뒤 커밋한다.
2. `tools/Install-ShuffleSocAppBundle.ps1`
   - App Upload timeout을 고정 60초에서 매개변수 기본 300초로 바꿨다.
   - Private App 방식을 계속 쓸지 결정되지 않았으므로 **지금 커밋하지 않는다**.

Terraform 현재 HEAD는 `6749ac0 (와주 안끝)`이다. Commit 메시지를 완료 증거로 읽지 않는다.

## 2.3 DVWA Git 상태 — 당시 Snapshot

- Worktree는 확인 가능한 범위에서 깨끗하다. `.pytest_cache` 조회 경고는 있었으나 추적
  변경은 출력되지 않았다.
- 현재 HEAD: `0997d2a Deploy DVWA sha-bf308add... [skip ci]`
- `deploy/dvwa/values.yaml`의 기준 상태는 `defaultSecurityLevel: low`다.
- v1 보안 레벨 전이 Workflow Source는 존재하지만 v2 Containment·Reset 계약이 아니다.

## 2.4 Wazuh — 11:56 KST 당시 미검증 Snapshot

당시 확인:

- `docker compose ps`는 Docker Linux Engine pipe 없음으로 실패했다.
- 따라서 Manager·Indexer·Dashboard의 **현재 실행, Rule Load, 수집, Dashboard 상태는 미검증**이다.
- Host 설정에는 다음이 있다.
  - DVWA Push JSONL `localfile`
  - 10분 Poll: CloudTrail, ALB, WAF, DVWA, CloudFront
  - Rule `100102`: 안전 Push Probe
  - Rule `100103`: DVWA `command.execution` + `ec2_imds` + `low`
  - Rule `100100`: CloudTrail S3 `GetObject` 대표 탐지
- 현재 `wazuh_manager.conf`에는 활성 `<integration>` 또는 `custom-shuffle-soc` 블록이 없다.
- Base Compose의 Manager·Indexer·Dashboard Port는 `0.0.0.0`에 노출되는 형태다. Local-only
  Override Source가 있어도 실제 Effective Compose 적용 여부는 다시 검증해야 한다.
- 세 서비스 모두 `restart: no`다. Docker Desktop만 켠다고 자동 시작된다고 가정하지 않는다.

이후 같은 날 Runtime 재확인에서 Docker Engine과 Wazuh 3개 Service가 실행 중이고 모든
노출 Port가 `127.0.0.1`에 바인딩된 것을 확인했다. Manager에는 Push JSONL localfile과
`custom-shuffle-soc`가 활성화돼 있었고 합성 Rule `100103` Alert도 존재했다. 그러나 실제
AWS `command.execution` 3 TAKE 저지연 검증은 여전히 미완료다.

과거 또는 보존 Evidence:

- CloudTrail S3 수집과 Rule `100100` Alert는 과거 Runtime Evidence가 있다.
- WAF와 DVWA Raw archive 도착도 과거 확인했다. 이것은 탐지·대응 완료가 아니다.
- Rule `100102` 안전 Probe 3회는 약 3~6초 도착 Evidence가 있다.
- 실제 `command.execution` Source Event 한 건은 JSONL에 있다.

중요 결함:

- 당시 보존 `command.execution` Event에는 `take_id`가 없었다.
- 이후 DVWA Source와 Baseline Runner에는 검증된 `X-SOC-TAKE-ID` 전달·감사 로직이 추가됐다.
- Source 추가는 실제 AWS Runtime 전달 증거를 대신하지 않는다.
- 해당 Event는 Event 시각과 Bridge 수신 사이가 약 39분이라 저지연 증거가 아니다.
- Rule `100103` 실제 Alert 3회, 정상 대조군 0건, 중복 0건 Evidence는 아직 없다.
- Offline Catch-up, DLQ 재처리, Docker 재기동 후 복구도 완료 Evidence가 없다.

## 2.5 Shuffle Cloud — 당시 Snapshot

사용자 수행 및 로컬 확인:

- Shuffle Cloud 계정 생성
- Private Workflow `CAPITAL-ONE-SOC-CONTAINMENT-v1` 생성
- Webhook Trigger 생성 및 사용자가 Start했다고 보고
- 공개 ID는 `soc-config/soc-lab.json`에 저장
- `shuffle_api_key`, `shuffle_webhook_url`, Webhook Header는 DPAPI CurrentUser 파일로 저장
- Private App ZIP과 Manifest는 로컬에 여러 버전 생성됨

아직 완료되지 않음:

- App Upload Evidence 없음
- Cloud Workflow Export 검증 없음
- 실제 Validator·Dedupe·Dispatcher 노드 구성 없음
- Gate B5 없음
- GitHub PAT Authentication 없음
- Wazuh → Shuffle 실제 Alert 전달 없음
- GitHub Dispatch·Argo·재공격·Reset E2E 없음

따라서 Shuffle은 **완성도 0에 가까운 입구 준비 상태**다. 화면에 Workflow와 Webhook이
보인다는 이유로 연동 완료라고 말하지 않는다.

---

## 3. 실무 원칙과 학생 환경을 다시 구분한 판정

| 항목 | 판정 | 근거와 적용 |
|---|---|---|
| 빠른 경보 경로와 원본 조사·보존 경로 분리 | 유지 | AWS는 CloudWatch Logs Subscription 같은 실시간 Feed와 중앙 Log Archive를 별도 목적으로 제공한다. 현재 Push와 10분 Poll의 이중 경로 자체는 타당하다. |
| Local Wazuh all-in-one | 조건부 유지 | Wazuh 공식 문서는 all-in-one을 Lab·Small 환경에 둔다. 학생 시연 Runtime으로는 가능하지만 Production-equivalent라고 부르면 안 된다. |
| Local Bridge | 조건부 보류 | AWS Event를 로컬 Wazuh가 받을 수 있게 하는 학생 환경 Adapter다. Wazuh Agent/DaemonSet/Sidecar 또는 접근 가능한 중앙 Manager의 정석을 대체하는 표준 구성이라고 말할 수 없다. 일정상 유지할 수는 있으나 Target Architecture에서는 교체 대상으로 표시한다. |
| TAKE_ID | 표현 보정 | 시연의 실행 식별자이자 Dedupe Allowlist다. 실무 일반 해법은 아니다. 실무 원칙은 안정적인 Incident/Event Correlation과 Idempotency다. |
| Rule `100103` 3회 | 범위 보정 | 프로젝트 Acceptance Evidence로는 쓸 수 있다. Production 안정성·SLO 증명은 아니다. |
| Wazuh custom sanitizer | 조건부 타당 | Wazuh 공식 문서는 `custom-` Integration을 지원한다. Shuffle Cloud로 민감정보를 보내지 않기 위한 최소 변환은 정당화할 수 있다. 단, 현재는 활성 Integration도 없고 Runtime 검증도 없다. |
| Shuffle Private Apps 두 개 | 재검토 | Shuffle Custom App은 공식 지원 기능이므로 불법 야매는 아니다. 그러나 Native Webhook·Condition·Datastore·HTTP로 가능한지 먼저 검증하지 않고 2개 App과 대형 검증 모듈부터 만든 것은 과설계였다. |
| GitHub Workflow → Git Commit → Argo CD | 대체로 유지 | GitOps 흐름은 공식 권장 패턴과 맞는다. 다만 같은 Source Repo의 `main` 직접 Push와 자동 배포는 Lab 절충안이며, 실무 Target은 별도 Config Repo·보호 Branch·승인 경계를 검토해야 한다. |
| DVWA Workload Quarantine | Target Containment | NetworkPolicy 집행이 실제 Runtime에서 증명된 뒤에만 격리로 인정한다. YAML 존재만으로 격리됐다고 말하지 않는다. |
| IAM 영향 범위 제한 | Target Containment | 현재 DVWA 권한은 공유 Karpenter Node Role에 있으므로 Role 전체 자동 차단은 금지한다. `validation/*` 실습 영향만 제한하거나 사람 승인을 요구한다. |
| `low → impossible` 자동 변경 | 시연 전용 Remediation | 실제 `values.yaml`을 바꾸는 애플리케이션 보안 설정 패치지만, 격리나 침해 원인 제거로 부르지 않는다. |
| Reset Commit | 유지 | History Rewrite나 강제 Push 없이 반대 방향의 새 Commit으로 복구하는 것은 GitOps와 양립한다. Argo auto-sync가 켜진 상태에서 이를 “Argo Rollback”이라고 부르지는 않는다. |
| 24시간·HA·모든 Source Push 제외 | 프로젝트 범위에서는 허용 | 프로젝트 완료 조건에서는 제외할 수 있다. 단, Production SOC의 불필요한 요소라고 말하면 틀리다. Target Architecture의 미구현 Gap으로 표시한다. |

### 잠정 권고안 — 사용자 재승인 전에는 구현하지 말 것

```text
학생 시연 As-built
DVWA CloudWatch Logs
→ AWS event-driven Push
→ Local Bridge (명시적인 Lab Adapter)
→ Local Wazuh Rule 100103
→ Wazuh의 Rule-filtered Integration
→ Shuffle Native Workflow 우선
→ Workload Quarantine + 제한된 IAM 영향 차단
→ 느린 증거 상관분석
→ GitOps Remediation (low → impossible)
→ 수동 Reset에서는 Quarantine을 마지막에 해제

Production Target
Workload Agent/DaemonSet/Sidecar 또는 중앙 수집 경로
→ 접근 가능한 중앙 Wazuh Cluster
→ SIEM Alert triage/correlation
→ SOAR의 사전 승인·가역적 Playbook
→ Ticket/Case·승인·감사·HA
```

Private App은 Native Workflow로 부족한 구체적 보안 속성이 증명될 때만 다시 도입한다.

---

## 4. 헛짓거리·실패·오판 기록

이 절은 책임 회피용 “시행착오” 미화가 아니라, 다음 세션이 반복하면 안 되는 행동 목록이다.

### 4.1 작업 방식 실패

1. 사용자가 이해하기 전에 계획·Script·Gate를 계속 늘렸다.
2. “왜 필요한가”를 합의하지 않고 `ㄱㄱ`를 넓은 구현 승인처럼 사용한 순간들이 있었다.
3. 사용자가 중지·설명·정리를 요구했는데도 다음 구현으로 넘어간 적이 있었다.
4. 정적 Test와 Source 준비를 Runtime Ready에 가깝게 표현했다.
5. 사용자가 직접 화면을 보며 배우려는 단계와 AI가 자동화해야 할 단계를 구분하지 못했다.
6. 장시간 subagent 작업 상태를 사용자 눈높이로 제때 요약하지 않아 사용자가 현재 단계를
   놓쳤다.
7. 대화 Context가 반복 압축되는데도 파일 기반 단일 인수인계점을 더 일찍 만들지 않았다.
8. 다이어그램 작업에서 디자인 기준을 합의하지 않은 채 버전을 반복 생산해 큰 시간과
   스트레스를 썼다. 이 기록은 SOC 구현과 분리하고 다시 끌고 오지 않는다.

### 4.2 아키텍처 실패

1. Wazuh를 어디에 두는 것이 실무 정석인지 먼저 설명하지 않고 로컬 구성부터 확장했다.
2. `수집`, `탐지`, `경보 전달`, `조사`, `자동 대응`을 여러 차례 섞어 설명했다.
3. 10분 Poll의 한계를 발견한 뒤 가능한 대안 전체를 비교하기보다 Lambda·SQS·Local
   Bridge 구현으로 너무 빨리 수렴했다.
4. Local Bridge를 학생 환경 Adapter가 아니라 필수 구성처럼 느끼게 만들었다.
5. Wazuh 공식 Shuffle Integration과 Shuffle Native Workflow를 최소 POC로 먼저 시험하지
   않고 Private Validator·Dispatcher App 설계로 넘어갔다.
6. `automation/SocLab.Shuffle.psm1`이 약 1,465줄까지 커지고 Gate·Hash·Cloud Provenance
   검증이 늘었지만, 정작 Wazuh Rule `100103` Runtime과 Wazuh→Shuffle 한 건도 끝내지 못했다.
7. “실무처럼”이라는 말을 배치·가용성·운영 인력까지 포함하는지 구분하지 않고 사용했다.
8. `TAKE_ID`와 `low → impossible`을 실무 일반 설계처럼 보이게 할 위험을 만들었다.

### 4.3 기술 실패

1. Wazuh AWS Reader IAM에서 `s3:ListBucket`이 없어 `AccessDenied`가 발생했다. Wazuh가
   먼저 Bucket Root를 List하는 실제 호출을 확인한 뒤 보정했다.
2. CloudFront 입력 형태를 설치된 Parser 계약과 먼저 대조하지 않아 직접 Custom S3
   수집이 맞지 않았다.
3. 실제 공격 Event가 와주 설치 전에 발생했거나 Bridge가 꺼져 있어 뒤늦게 수집된 것을
   저지연 경로로 오해할 뻔했다.
4. 현재 실제 `command.execution`에는 `take_id`가 없는데 이후 sanitizer는 이를 필수로
   요구한다. Source 계약과 전달 계약이 끊겨 있다.
5. Wazuh Manager 설정에 Shuffle Integration이 실제로 없는데 Template·Script 존재를
   구현으로 취급했다.
6. GitHub Dispatch의 `return_run_details=true`를 충분한 공식 확인 없이 고정했다.
   이후 API `2026-03-10` 공식 계약이 이 Parameter를 제거하고 항상 HTTP 200 Run Details를
   반환함을 확인했으므로, Legacy Dispatcher 1.0.0은 v2 Binding에서 제외한다.
7. Shuffle Upload가 60초 timeout 난 뒤 구조를 재검토하기보다 timeout을 300초로 늘리는
   수정부터 했다. 이 변경은 아직 미커밋이며 Private App 채택 결정 뒤 판단한다.
8. Daily Down에서 Terraform 밖의 고아 VPC CNI ENI 하나가 SG·Subnet 삭제를 막았다.
   사용자 승인 뒤 정확한 ENI 속성을 재검증하고 해당 ENI만 삭제한 다음 Destroy를
   완료했다. 기존 Karpenter cleanup은 EC2 Instance만 다루고 ENI를 다루지 않았다.
9. Daily Down 재개 중 기본 Evidence 경로 쓰기가 Sandbox에서 거부되어 별도 writable
   Evidence Root로 재시도했다.
10. Daily Up에서 Native command 성공 출력이 함수 반환 Stream을 오염시켜 `$image`가
    배열이 됐고 `.Repository` 접근에서 실패했다. Apply 자체는 이미 성공한 뒤였다.
11. 상태 확인 과정에서 `terraform output -json`을 사용해 sensitive output까지 Agent
    Tool Output으로 읽는 실수를 했다. 값은 이 문서나 답변에 복사하지 않았지만, 앞으로
    절대 전체 output을 읽지 말고 비민감 Output만 이름으로 선택한다. 해당 Daily Runtime의
    일회성 DB Credential은 종료 시 자원과 함께 폐기되는 것으로 취급한다.
12. 현재 Runtime을 올리면서 Watchdog를 `Off`로 두었다. 비용 종료 책임이 자동화돼 있지 않다.

### 4.4 맞았지만 과장하면 안 되는 것

- 안전 Push Probe 3회는 DVWA Push Transport가 Wazuh까지 도착할 수 있음을 보였다.
  실제 공격 탐지 3회를 증명하지 않는다.
- 5개 Source가 설정에 존재하거나 Raw Archive에 도착한 것은 수집 Coverage다.
  의미 있는 탐지 Rule·오탐 검증·대응 완성을 뜻하지 않는다.
- Private App Source와 Test가 통과한 것은 Package 구조 증거다. Shuffle Cloud Runtime
  성공을 뜻하지 않는다.
- GitHub Workflow Source가 안전장치를 가진 것은 좋은 출발이다. 실제 Token 권한,
  Dispatch exactly-once, Commit, Argo 배포는 아직 E2E 증거가 없다.

---

## 5. 다음 세션의 정확한 작업 순서

## Gate 0 — 비용·Git·Runtime 동결

- AWS Daily Runtime 사용 여부를 사용자에게 먼저 알린다.
- `git status --short`를 Terraform과 DVWA에서 확인한다.
- 기존 두 미커밋 파일을 보존한다.
- Shuffle App Upload·PAT·실제 공격은 하지 않는다.

## Gate 1 — Wazuh 현재 Runtime 복구와 최소 보안 확인

사용자에게 각 명령의 의미를 설명하면서 수행한다.

확인 항목:

- Docker Desktop Engine 실행
- `docker compose config` 성공
- Effective Port가 `127.0.0.1`인지 여부
- Manager·Indexer·Dashboard 실행
- `wazuh-modulesd -t` 성공
- `capital_one_rules.xml` 실제 Load
- Push JSONL `localfile` 실제 Load
- 5 Source Poll 설정 실제 Load
- 기본 Credential 변경과 현재 Secret override 적용 여부
- 설정·Index·Dashboard 영속성

이 Gate를 통과하기 전에는 “Wazuh 완료”라고 말하지 않는다.

## Gate 2 — Rule 100103 실제 탐지 계약 수정·검증

먼저 Source Event와 sanitizer의 `take_id` 불일치를 해결할 최소 설계를 합의한다.

그 뒤 독립 TAKE 3회:

- TAKE당 실제 `command.execution` Source Event 수
- Rule `100103` Alert 수
- 정상 숫자 IP Ping 대조군 Alert 0
- Event → Wazuh Alert 지연
- Event ID·Hash·TAKE_ID 연결
- 누락·중복
- 원문 Command, Response, Credential, Cookie, Token 비노출

3회는 프로젝트 Gate일 뿐 Production 보증이라고 말하지 않는다.

## Gate 3 — Wazuh→Shuffle 최소 경로 결정

먼저 비교할 것:

1. Wazuh 공식 `<integration><name>shuffle</name>` + `rule_id=100103`
2. Wazuh `custom-` sanitizer + Shuffle Webhook
3. 현재 Private App 2개 구조

판단 기준:

- Rule `100103`만 전달 가능한가
- 민감 필드를 Wazuh 밖으로 내보내지 않는가
- 사용자가 유지보수 가능한가
- 중복 대응과 실패가 관측 가능한가
- 공식 지원 범위와 Custom code 범위가 어디까지인가

기본 방향은 Native Workflow 우선이다. Custom은 Native로 충족하지 못하는 요구를 구체적으로
증명할 때만 남긴다.

## Gate 4 — Shuffle Dry Run

- Webhook 인증
- 허용 Schema와 Allowlist
- 동일 사건 Dedupe
- GitHub 대신 Stub
- 정상·거부·중복 분기
- Workflow Export와 Runtime Evidence

Private App을 채택하지 않으면 기존 Bundle과 `Install-ShuffleSocAppBundle.ps1`은
`시행착오/`로 이동할 후보이지만, 사용자 승인 전에는 이동·삭제하지 않는다.

## Gate 5 — 제한된 Containment

- NetworkPolicy 집행 가능 CNI와 실제 차단을 먼저 증명
- DVWA Workload Quarantine 적용과 가역성 확인
- 공유 Karpenter Node Role 전체 자동 차단 금지
- `validation/*` 실습 영향만 제한하거나 `IAM_APPROVAL_REQUIRED`로 종료
- 동일 Incident 재전달 시 Containment 재실행 0회

## Gate 6 — 느린 증거 상관분석과 Remediation

- WAF·ALB·CloudFront·DVWA Poll·CloudTrail을 같은 Incident에 Enrichment
- 예상한 CloudTrail `GetObject` 성공으로 침해를 확정하되 Containment 재실행 금지
- 별도 GitOps Workflow로 `low → impossible`만 변경
- Git Commit SHA, Argo `Synced / Healthy`, 새 Pod와 공격 실패 확인
- 이 변경은 애플리케이션 설정 Remediation이며 Containment라고 부르지 않음

## Gate 7 — 수동 Reset과 최종 E2E

- Evidence와 Git History를 삭제하지 않고 새 Reset Commit 사용
- Quarantine을 유지한 채 `impossible → low`와 실습 IAM 권한만 복원
- 새 Pod·Alarm `OK`·Wazuh/Bridge `READY`·새 TAKE 확인
- 모든 조건 통과 뒤 Quarantine을 마지막에 해제
- 실패하거나 자리를 비우면 재격리하거나 Daily Runtime 종료

```text
READY
→ 실제 공격
→ Rule 100103
→ Shuffle Incident 1개
→ Workload/IAM 영향 Containment exactly 1
→ 느린 증거 Enrichment와 침해 확정
→ GitOps Remediation Commit
→ Argo 배포·재공격 실패·정상 기능 유지
→ 수동 Reset (Quarantine 마지막 해제)
```

한 TAKE의 Evidence로 모두 이어질 때만 완료다.

---

## 6. 다음 세션에 붙여 넣을 시작 프롬프트

```text
D:\terraform\aws_terraform_build_code\CAPITAL-ONE-INCIDENT-RESPONSE-SCENARIO.md,
CAPITAL-ONE-SOC-DEMO-PLAN.md, CAPITAL-ONE-SOC-E2E-BLUEPRINT.md를 이 순서로 읽어.
그 뒤 SOC-LAB-SESSION-HANDOFF-2026-08-18.md는 역사 기록과 Runtime 단서로만 사용해.

새 구현, Shuffle App Upload, PAT 등록, 실제 공격부터 하지 마.
먼저 실제 DVWA command.execution → Wazuh Rule 100103 독립 3 TAKE를 observe-only로
완료해. 지연·중복·누락·오프라인 catch-up·DVWA Poll rollback을 검증하기 전에는
Containment·Remediation·Reset을 구현하지 마. Source 존재, 과거 Evidence, 현재 Runtime,
Target을 분리해.

Local Bridge·Private Shuffle Apps·TAKE_ID·low→impossible을 실무 표준처럼 정당화하지
말고, low→impossible은 Remediation으로만 분류해. 공식 Wazuh/AWS/Shuffle/GitHub/Argo/NIST
근거와 로컬 Evidence를 각각 분리해 판단해.
각 행동 전에 왜 필요한지 설명하고 사용자 승인 경계를 지켜.
```

---

## 7. 핵심 파일 지도

### 현재 판단의 기준

- `CAPITAL-ONE-INCIDENT-RESPONSE-SCENARIO.md` — 대응 의미와 순서의 정본
- `CAPITAL-ONE-SOC-DEMO-PLAN.md` — 현재 Gate·촬영 범위·우선순위
- `CAPITAL-ONE-SOC-E2E-BLUEPRINT.md` — v2 Target 계약과 완료 조건
- `SOC-LAB-SESSION-HANDOFF-2026-08-18.md` — 역사 기록과 Runtime 단서
- `SOC-LAB-OPERATOR-HANDOFF.md` — 과거 Custom Shuffle 운영 절차, 현재 실행 금지

### Wazuh

- `observability/wazuh/README.md`
- `observability/wazuh/WAZUH-PUSH-TRANSPORT-DESIGN.md`
- `D:\Wazuh\wazuh-docker\single-node\config\wazuh_cluster\wazuh_manager.conf`
- `D:\Wazuh\wazuh-docker\single-node\config\wazuh_cluster\rules\capital_one_rules.xml`
- `C:\Users\Unoh\Documents\aws-topology-evidence\wazuh-push-shadow\dvwa\wazuh-push-live.jsonl`

### Shuffle — 모두 미완료로 취급

- `observability/shuffle/SHUFFLE-CLOUD-SETUP.md`
- `automation/SocLab.Shuffle.psm1`
- `tools/Install-ShuffleSocAppBundle.ps1`
- `C:\Users\Unoh\AppData\Local\aws-topology\soc-config\soc-lab.json`
- `C:\Users\Unoh\Documents\aws-topology-evidence\shuffle-packages\`

### Deployment

- `D:\DVWA\.github\workflows\soc-contain-dvwa.yml` — Legacy v1, Production 실행 금지
- `D:\DVWA\.github\workflows\soc-reset-dvwa.yml` — Legacy v1 Reset 일부만 구현
- `D:\DVWA\deploy\dvwa\values.yaml`
- `D:\DVWA\gitops\argocd\dvwa.yaml`

### Daily Runtime

- `daily-up.ps1`
- `daily-down.ps1`
- `C:\Users\Unoh\AppData\Local\aws-topology\daily-session\active-session.json`
- `C:\Users\Unoh\AppData\Local\aws-topology\daily-session\logs\20260818T015429Z-08b56734.log`

---

## 8. 근거 등급과 공식 참고

### 로컬 1차 근거

- 현재 Git Diff와 Runtime 출력
- Wazuh Host 설정·Rule·JSONL
- Terraform Session State와 Daily wrapper log
- 실제 GitHub/DVWA Source
- 보존 Evidence

### 공식·표준 근거

- Wazuh Architecture:
  https://documentation.wazuh.com/current/getting-started/architecture.html
- Wazuh Kubernetes Agent DaemonSet·Sidecar:
  https://documentation.wazuh.com/current/deployment-options/deploying-with-kubernetes/kubernetes-deployment.html
- Wazuh 외부 API·Shuffle Integration:
  https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html
- AWS CloudWatch Logs Subscriptions:
  https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Subscriptions.html
- AWS Incident Response Containment:
  https://docs.aws.amazon.com/security-ir/latest/userguide/contain.html
- NIST SP 800-61r3:
  https://csrc.nist.gov/pubs/sp/800/61/r3/final
- GitHub Actions Secure Use:
  https://docs.github.com/en/actions/reference/security/secure-use
- Argo CD CI Automation:
  https://argo-cd.readthedocs.io/en/stable/user-guide/ci_automation/
- Argo CD Best Practices:
  https://argo-cd.readthedocs.io/en/release-2.12/user-guide/best_practices/

### 비공식 참고의 한계

Wazuh·Shuffle·TheHive를 조합한 Home Lab이나 Vendor Case는 해당 조합이 실제 존재한다는
증거로만 사용한다. 시장 전체의 표준이나 현재 프로젝트의 정답을 증명하지 않는다.

---

## 9. Secret 취급

- API Key, PAT, Webhook URL/Header, Wazuh Password, Terraform sensitive output은 채팅·Git·
  Screenshot·Evidence에 복사하지 않는다.
- `soc-secrets/*.dpapi.json`의 존재만 확인하고 내용은 열지 않는다.
- `terraform output -json` 전체 조회를 금지한다.
- 필요하면 정확히 비민감 Output 하나만 `terraform output -raw <name>`으로 읽는다.
- 이 문서에는 Secret 값이 없다.

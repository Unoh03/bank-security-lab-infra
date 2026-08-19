# Capital One 기반 침해 대응 시나리오

> **상태:** CURRENT DECISION — 대응 의미와 Gate 순서 확정, 후속 대응 구현은 미완료
>
> **기준 시점:** 2026-08-18
>
> **정본 범위:** 탐지 이후 Containment·Investigation·Remediation·Recovery·재촬영 Reset
>
> **우선순위:** 실제 `command.execution → Wazuh Rule 100103` Gate를 먼저 닫는다.
> 그 전에는 NetworkPolicy·IAM 차단·Remediation·Reset을 Runtime 완료로 표현하지 않는다.

이 문서는 대표 시연의 **대응 의미**를 정하는 단일 기준이다. 전달 구조와 필드 계약은
`CAPITAL-ONE-SOC-E2E-BLUEPRINT.md`, 전체 Gate와 완료 조건은
`CAPITAL-ONE-SOC-DEMO-PLAN.md`, 촬영 범위·화면·조작·내레이션은
`CAPITAL-ONE-SOC-DEMO-RECORDING-SCRIPT.md`를 사용한다. 서로 충돌하면 대응 의미는 이
문서를 우선하되, 실제 Source와 Runtime Evidence가 문서보다 우선한다.

---

## 1. 최종 판단

대표 시나리오는 다음 순서를 사용한다.

```text
DVWA command.execution 탐지
→ 의심 Workload와 실습 데이터 접근 영향의 즉시·가역적 Containment
→ 느린 5-Source Evidence로 공격 경로·성공 여부·영향 조사
→ DVWA low → impossible 보안 설정 패치(Remediation)
→ IAM·IMDS·Node·애플리케이션의 근본 원인 제거
→ 격리 해제·정상 기능·재공격 Negative Test
→ Recovery·사후 검토
```

`low → impossible`은 실행 동작을 바꾸는 실제 배포 변경이므로 **애플리케이션 보안 설정
패치**라고 부를 수 있다. 그러나 침해 자산이나 유출 자격증명을 격리하지 않으므로
Containment 또는 Credential Revocation이라고 부르지 않는다. 소스코드 자체를 수정하지
않으므로 발표에서는 `코드 패치`보다 `보안 설정 패치` 또는 `Remediation 배포`를 사용한다.

느린 CloudTrail Event를 기다린 뒤에야 처음 대응하는 구조도 사용하지 않는다. Rule
`100103`의 고신뢰 조건으로 좁고 가역적인 Containment를 먼저 수행하고, CloudTrail Rule
`100100`과 WAF·ALB·CloudFront는 Incident를 확인·보강한다.

---

## 2. 실무 원칙과 시연 각색의 경계

### 실무 원칙으로 유지할 것

- 탐지·분석·Containment·Remediation·Recovery의 목적을 섞지 않는다.
- 빠른 자동 조치는 고신뢰 신호, 좁은 범위, 가역성, 감사 기록을 전제로 한다.
- 자산 격리와 Identity·Credential 영향 차단을 별도로 판단한다.
- 증거를 보존한 뒤 취약점과 지속성 원인을 제거하고 정상 기능을 검증한다.
- 자동 조치는 대상과 권한이 사전 Allowlist된 경우에만 실행한다.
- 공유 Role·공유 Node처럼 Blast Radius가 큰 대상은 자동 Deny하지 않는다.
- Reset은 운영 Recovery가 아니라 통제된 촬영 환경을 다시 여는 별도 절차다.

### 학생 시연에 맞게 축소할 것

- 실제 SSRF 대신 DVWA Command Injection을 진입점으로 사용한다.
- 24시간 SOC가 아니라 노트북이 켜진 예약된 TAKE 시간창에서 실행한다.
- NetworkPolicy와 IAM 조치는 `CAPITAL-ONE` Lab 대상만 다룬다.
- `low → impossible`은 실제 조직의 범용 치료 코드가 아니라 DVWA 전용 설정 패치다.
- 느린 Source는 실시간 대응 Trigger가 아니라 조사 Timeline과 보고서 Evidence로 사용한다.

---

## 3. 현재 As-built와 Target을 분리한다

| 항목 | 현재 Source·Runtime | Target | 현재 판정 |
|---|---|---|---|
| DVWA Push | Lambda·SQS·Local Bridge·JSONL·Rule `100102` 무해 검증 존재 | 실제 공격 Rule `100103` 3 TAKE | **현재 최우선 Gate** |
| Rule `100103` | Rule과 합성 검증 Alert 존재 | 실제 AWS `command.execution` 저지연 반복 검증 | 미완료 |
| 느린 Evidence | 5-Source 10분 Poll·보존 화면 존재 | 조사·확인 경로로 유지 | 역할 확정 |
| Workload 격리 | 적용 Source·Runtime Evidence 없음 | DVWA 전용 Quarantine NetworkPolicy | 미구현 |
| NetworkPolicy 강제 | EKS VPC CNI의 Network Policy 활성 Evidence 없음 | Enforcing CNI와 실제 Deny/Allow Test | 미검증 |
| IAM 영향 차단 | DVWA 권한이 공유 Primary Karpenter Node Role에 연결 | Lab Prefix 임시 Deny 또는 전용 Principal Containment | 미구현 |
| Remediation | 분리된 실행 Source·Runtime Evidence 없음 | Containment 뒤 `low → impossible` 설정 패치 | 미구현 |
| Reset | 전체 복원 순서의 Source·Runtime Evidence 없음 | 격리·IAM·설정 상태를 안전한 순서로 복원 | 미구현 |
| Wazuh → Shuffle | 최소 Schema와 Custom Integration Source 존재 | 먼저 `observe_only`, 이후 승인된 대응 분기 | E2E 미완료 |

분리된 Containment·Remediation·Reset 계약을 Source와 Runtime으로 각각 검증하기 전에는
Production 대응 경로에서 호출하지 않는다. 이름이 비슷한 파일이나 기존 Source의 존재를
새 시나리오 구현 완료로 세지 않는다.

---

## 4. 단계별 대응 시나리오

### Phase 0 — Preparation

촬영 전 다음 조건을 만족해야 한다.

- Wazuh·Bridge·Rule `100103`이 READY이고 새 `TAKE_ID`가 발급됐다.
- DVWA는 `low`, Argo CD는 예상 Revision으로 `Synced + Healthy`다.
- 실습 Object와 권한은 `validation/*`에만 한정된다.
- 이전 TAKE의 임시 Credential이 공격 Process 환경에 남아 있지 않다.
- Quarantine과 IAM 임시 Deny의 적용·해제 Target이 고정돼 있다.
- NetworkPolicy가 실제로 강제되는지 별도 Positive/Negative Test를 통과했다.
- IAM 자동 조치가 공유 Role 전체를 중단시키지 않는다는 Blast Radius 검토가 끝났다.

마지막 두 조건이 없으면 대응은 `observe_only` 또는 사람 승인 모드로만 실행한다.

### Phase 1 — Detection and Analysis

```text
DVWA 안전 Audit CWL
→ Subscription → Lambda Allowlist → SQS → Local Bridge
→ Wazuh Rule 100103
```

빠른 Trigger 조건:

- `source=dvwa`
- `transport=push`
- `event_type=command.execution`
- `result=succeeded`
- `context.resource=ec2_imds`
- 승인 Account·Region·Route·Scenario

Rule `100103`은 **IMDS를 겨냥한 명령 실행 성공 Event**를 의미한다. 이것만으로 임시
Credential 탈취나 S3 `GetObject` 성공까지 확정했다고 주장하지 않는다.

### Phase 2 — Immediate Containment

첫 Alert가 유효하면 Shuffle은 같은 `TAKE_ID`의 `incident_confidence`를 `SUSPECTED`로
만들고 `response_phase`를 `DETECTED`로 기록한 뒤, 동일 Source `event_id`와 TAKE 대응을
중복 차단한다. 확신도와 대응 단계는 서로 다른 필드다.

#### 2-A. Workload Containment

고정된 DVWA Label만 선택하는 Quarantine NetworkPolicy를 적용한다.

```text
대상: namespace=dvwa,
      app.kubernetes.io/name=dvwa,
      app.kubernetes.io/instance=dvwa
기본: Ingress·Egress 차단
예외: 검증된 Health·DNS·관측 경로만 최소 허용
금지: 임의 Namespace·Selector·CIDR 입력
```

YAML 존재만으로 성공 처리하지 않는다. EKS의 Network Policy enforcing 기능과 실제
허용·차단 Test가 모두 필요하다. 격리 후에도 기존 Pod·Node·Wazuh Evidence를 삭제하지
않는다.

#### 2-B. IAM Impact Containment

현재 Credential Source는 공유 Primary Karpenter Node Role이므로 Role 전체 Deny·비활성화를
무조건 자동 실행하지 않는다. 다음 두 모드만 허용한다.

| 조건 | 허용 조치 | 표현 |
|---|---|---|
| 현재 공유 Role | `validation/*` 실습 자산에 대한 사전 검토된 임시 Explicit Deny 또는 사람 승인 | Lab 데이터 접근 영향 차단 |
| 향후 DVWA 전용 Role·Node | 사전 승인된 Principal Containment와 Session 영향 차단 | IAM Principal Containment |

Lab Prefix Deny는 유출 Credential 자체를 무효화하지 않는다. 따라서 발표에서도
`Credential 폐기`가 아니라 `실습 데이터 추가 접근 차단`이라고 설명한다.

### Phase 3 — Investigation and Confirmation

다음 느린 Evidence를 Wazuh에서 같은 Incident Timeline으로 연결한다.

- WAF: 요청 검사 결과와 Label
- ALB·CloudFront: 외부 요청 경로와 시각
- DVWA Poll: 원본 감사 Event 재확인
- CloudTrail Rule `100100`: 예상 Role의 `validation/* GetObject` 성공 여부
- EKS·Argo Evidence: 이후 대응 배포와 Workload 변경

CloudTrail 성공 Event가 도착하면 `incident_confidence`만 `CONFIRMED`로 갱신한다.
`response_phase=CONTAINED` 또는 `INVESTIGATING`은 그대로 유지하며, 늦은 확인 Event가
이미 수행한 Containment를 다시 실행하지 않는다. 정상 사용자나 다른 Object의 Event를
같은 Incident에 억지로 합치지 않는다.

### Phase 4 — Eradication and Remediation

증거 보존과 범위 확인 뒤 다음 순서로 원인을 제거한다.

1. DVWA `defaultSecurityLevel: low → impossible` 보안 설정 패치를 GitOps로 배포한다.
2. Argo CD가 정확한 Commit SHA를 `Synced + Healthy`로 배포했는지 확인한다.
3. 새 Pod에서 동일 Command Injection이 애플리케이션 계층에서 실패하는지 확인한다.
4. Terraform으로 실습 IAM 권한 제거·최소 권한, IMDSv2 강제, Hop Limit, 필요한 Node
   교체를 계획하고 사람 승인 뒤 적용한다.
5. 필요하면 취약 애플리케이션 코드·Image를 별도 Patch한다.

`low → impossible` 검증 때는 NetworkPolicy 때문에 실패한 것과 설정 패치 때문에 실패한
것을 구분한다. 애플리케이션 Remediation의 Negative Test는 필요한 접근 경로를 제한적으로
복구한 뒤 수행하되, IAM 임시 Deny는 영구 IAM 복구가 확인될 때까지 유지한다.

### Phase 5 — Recovery

다음 조건을 모두 만족한 뒤에만 격리를 해제한다.

- 예상 Remediation Commit이 배포됐다.
- 동일 공격이 실패하고 정상 로그인·허용 기능은 성공한다.
- 실습 IAM 권한과 IMDS 경로가 목표 상태다.
- 기존 탈취 Credential의 `validation/*` 접근이 `AccessDenied`다.
- 새 Rule `100103`·CloudTrail 위협 Event가 관찰창 동안 증가하지 않는다.
- 임시 NetworkPolicy·IAM Deny의 해제 주체와 시각이 Evidence에 남는다.

정상 운영 복귀 후에도 Wazuh Alert와 원본 로그를 삭제하지 않는다.

### Phase 6 — Post-incident

- 탐지·Containment·확인·Remediation·Recovery 시간을 각각 기록한다.
- 오탐, 누락, 중복 대응, 서비스 영향과 수동 개입을 기록한다.
- 공유 Node Role이 만든 자동화 한계를 보고서에 남긴다.
- 영구 통제로 전환할 항목과 학생 시연에서만 유지할 항목을 분리한다.

---

## 5. Trigger와 조치 결정표

| 입력 | Incident 확신도 | 자동 조치 | 하지 않는 주장 |
|---|---|---|---|
| Rule `100103` 첫 유효 Event | `SUSPECTED` | Workload Quarantine, 허용된 IAM 영향 차단 | S3 접근 성공 확정 |
| 같은 TAKE의 두 번째 명령 Event | 기존 Incident 보강 | 새 격리 없음 | Event 삭제·은폐 |
| Rule `100100` 예상 `GetObject` 성공 | `CONFIRMED` | Timeline·영향 갱신, 기존 격리 유지 | Containment 재실행 |
| WAF 단독 Event | 변경 없음 | 조사 보강 | 자동 격리 |
| 잘못된 TAKE·Account·Route | 변경 없음 | `REJECTED` Outcome, Incident 미생성 | 허용 범위 확대 |
| NetworkPolicy 미강제·공유 Role 위험 | `OBSERVE_ONLY` 또는 승인 대기 | Alert·Evidence만 보존 | 자동 대응 완료 |

---

## 6. 재촬영용 수동 Reset

Reset은 Incident Recovery가 아니다. 이미 제거한 취약 조건을 통제된 촬영을 위해 다시
여는 **Lab 전용 역방향 절차**다. 자동 Trigger와 SOAR는 Reset을 호출할 수 없다.

안전한 순서:

1. 이전 TAKE를 `CLOSED`로 표시하고 모든 Evidence·Hash를 보존한다.
2. Quarantine을 유지한 채 `impossible → low` Reset Commit을 배포한다.
3. Lab Prefix의 임시 IAM Deny를 제거하거나 전용 Lab 권한을 복원한다.
4. 새 Pod·Alarm 실제 `OK`·Credential 환경 정리·Wazuh·Bridge READY를 확인한다.
5. 새 TAKE를 발급한다.
6. Quarantine을 **마지막에** 해제하고 제한된 촬영 시간창을 시작한다.
7. 준비 실패·통제권 상실·자리 비움이면 즉시 다시 격리하거나 Daily Runtime을 종료한다.

Reset 완료 조건:

- History Rewrite·Force Push·기존 로그 삭제 없음
- 정확한 Reset Commit과 Argo Revision 일치
- 새 Pod의 `low` 확인
- 임시 IAM Deny 제거 대상이 `validation/*` 또는 전용 Lab Principal로 한정
- NetworkPolicy 해제 전 새 TAKE와 관측 경로 READY
- 이전 Credential이 Process 환경에 남지 않음
- 새 TAKE가 이전 Event ID와 섞이지 않음

최종 채택 영상을 확인한 뒤에는 Reset하지 않고 영구 복구로 이동한다.

---

## 7. 구현 Gate 순서

| 순서 | Gate | 종료 조건 |
|---:|---|---|
| 1 | Fast AWS → Wazuh | 실제 `command.execution → Rule 100103` 3 TAKE, 지연·누락·중복·대조군 확인 |
| 2 | Transport resilience | Offline Catch-up·DLQ·DVWA Poll Rollback 검증 |
| 3 | Wazuh → Shuffle observe-only | Sanitized Payload·Allowlist·Dedup·GitHub 호출 0 |
| 4 | Workload Containment | NetworkPolicy enforcement·대상·차단·관측·Rollback Runtime 검증 |
| 5 | IAM Impact Containment | 공유 Role용 Lab Prefix Deny 또는 전용 Principal, Blast Radius·Rollback 검증 |
| 6 | Remediation | `low → impossible` 정확한 Diff·Argo SHA·애플리케이션 Negative Test |
| 7 | Recovery | 영구 IAM·IMDS 복구, 격리 해제, 정상 기능·재공격 실패 |
| 8 | Retake Reset | Evidence 보존, 안전한 역순 복원, 새 TAKE 독립성 |

앞 Gate의 Runtime Evidence가 없으면 뒤 Gate의 Source 존재로 대체하지 않는다.

---

## 8. 공식 근거

- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final): Incident Response를
  CSF 2.0의 Detect·Respond·Recover와 조직 위험 관리에 통합한다.
- [CISA Incident Response Playbook](https://www.cisa.gov/sites/default/files/2024-08/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf):
  Containment 뒤 증거 보존, Eradication·Recovery와 재진입 모니터링을 분리한다.
- [AWS EKS Incident response and forensics](https://docs.aws.amazon.com/eks/latest/best-practices/incident-response-and-forensics.html):
  Pod·Node 격리, NetworkPolicy, Credential 대응, 증거 보존과 재배포를 다룬다.
- [AWS Security Incident Response — Contain](https://docs.aws.amazon.com/security-ir/latest/userguide/contain.html):
  Containment를 단계적이고 가역적으로 수행하고 운영 영향과 증거 보존을 고려한다.
- [AWSSupport-ContainIAMPrincipal](https://docs.aws.amazon.com/systems-manager-automation-runbooks/latest/userguide/awssupport-contain-iam-principal.html):
  IAM Principal에 Deny를 적용하는 가역적 Runbook이며 Workload 영향 검토와 Dry Run이 필요하다.
- [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/):
  NetworkPolicy를 지원·강제하는 네트워크 구현이 없으면 정책 Resource만 만들어도 효과가 없다.
- [EKS VPC CNI Network Policy](https://docs.aws.amazon.com/eks/latest/userguide/cni-network-policy-configure.html):
  EKS에서 Network Policy 기능을 명시적으로 구성하고 검증해야 한다.
- [Microsoft Defender Automatic Attack Disruption](https://learn.microsoft.com/en-us/defender-xdr/automatic-attack-disruption):
  고신뢰 공격 신호에 대해 Device·Identity·Session을 빠르게 격리하고 이후 조사·Remediation을
  이어가는 비교 사례다.

이 자료들이 특정 제품 조합을 의무화하지는 않는다. 이 시나리오는 공통 원칙인 좁은 자동
격리, Identity 영향 차단, 증거 보존, 별도 Remediation과 Recovery를 실습 환경에 맞춰 적용한다.

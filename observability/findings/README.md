# Finding F2

F2는 GuardDuty Finding을 많이 만드는 기능이 아니라, **Finding 하나를 조사 가능한 증거 시작점으로 바꾸는 최소 경로**다.

```text
GuardDuty
→ EventBridge
├─ CloudWatch Logs 30일 원본 전달
└─ 기존 SNS 알림 경계
→ Finding ID 기반 조사
→ 관련 Query와 Evidence Bundle
```

## 범위

- Primary Region GuardDuty 기본 탐지
- 선택형 Protection Plan은 모두 명시적으로 `DISABLED`
- EventBridge 원본 전달과 기존 SNS 연결
- AWS 공식 Sample Finding 1건으로 전달 경로 검증
- Finding ID에서 시간창·Entity·후속 Query를 자동 도출

현재 포함하지 않는 것:

- Security Hub
- Detective
- OpenSearch
- Lambda 상시 정규화
- 상시 SIEM
- GuardDuty Runtime Monitoring, Malware Protection 등 선택형 유료 기능

## 실행

먼저 Preview만 확인한다.

```powershell
.\observability\findings\Invoke-F2.ps1
```

Foundation Apply와 Sample Finding 실행 승인을 받은 뒤에만 다음을 사용한다.

```powershell
.\observability\findings\Invoke-F2.ps1 `
  -ConfirmRun 'RUN F2 SAMPLE FINDING'
```

실제 Finding은 공격자 IP나 공격 종류를 먼저 입력하지 않고 ID 하나로 조사한다.

```powershell
.\observability\findings\Invoke-FindingInvestigation.ps1 `
  -FindingId '<32자리 GuardDuty Finding ID>'
```

## 판정 경계

Sample Finding은 다음만 증명한다.

- GuardDuty API에서 Finding이 생성됨
- EventBridge Rule이 이를 받아 CloudWatch Logs에 보존함
- SNS Target이 구성돼 있음
- Finding ID에서 조사 시간창과 Query Plan을 만들 수 있음

Sample Finding은 실제 EC2 공격, 실제 Network Traffic, 실제 침해를 증명하지 않는다.
실제 시나리오의 차단·통과·로그 연결은 별도 Runtime Evidence로 판정한다.

# Capital One Gate 3 검증 회고와 보고서 재료

> **용도:** 정상 대조군 검증의 결과·시행착오·개선사항을 최종 보고서에서 재사용한다.
> **기준 시점:** 2026-08-12
> **검증 대상:** 정상 운영자의 고정 S3 `GetObject`는 기록되지만 Karpenter Node Role 탐지 Alarm은 울리지 않는가
> **공개 경계:** 원본 Bundle의 Account ID·Bucket·ARN·IP·Request ID는 이 문서에 옮기지 않는다.

---

## 1. 이 검증이 필요한 이유

공격 요청에서 Alarm이 울렸다는 사실만으로 탐지 Rule이 적절하다고 말할 수 없다.
같은 Object를 정상 운영자가 읽었을 때도 Alarm이 울리면 오탐이기 때문이다.

Gate 3은 다음 두 조건을 함께 확인했다.

```text
정상 접근도 CloudTrail에는 남아야 한다.
그러나 공격 Role 조건과 다르므로 대표 Alarm은 울리지 않아야 한다.
```

이는 “로그가 없다”를 정상으로 취급하는 Test가 아니다. **로그 수집 성공과 탐지 제외를
동시에 증명하는 Negative Control**이다.

---

## 2. Runtime에서 확인한 결과

Experiment:

```text
capital-one-negative-20260812T034935Z
```

확인된 결과:

```text
고정 정상 terra-user가 고정 가짜 CSV를 GetObject
가짜 데이터 Marker·5행·준비 SHA-256 일치
CloudTrail 성공 GetObject 정확히 1행
Primary Karpenter Node Role이 아님
Capital One Alarm은 OK 유지
Alarm State Updated Timestamp 불변
Evidence Bundle SHA256SUMS 50개 일치
```

따라서 현재 대표 Rule에 대해서는 다음처럼 말할 수 있다.

> Karpenter Node Role의 `validation/*` 성공 `GetObject`는 탐지했고, 같은 Object에 대한
> 고정 정상 운영자 접근은 기록하되 Alarm에서 제외했다.

이 결과는 모든 정상 사용자·모든 S3 접근에 대한 오탐 부재를 증명하지 않는다.

---

## 3. 왜 검증이 오래 걸렸는가

세 원인을 구분해야 한다.

### 3.1 AWS의 정상적인 전달 지연

CloudTrail은 Event 발생과 CloudWatch Logs 도착이 동시에 일어나지 않는다. AWS 공식
문서는 CloudTrail Event가 CloudWatch Logs에 평균 약 5분 안에 전달되지만 그 시간은
보장되지 않는다고 설명한다.

- AWS CloudTrail: <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html>

따라서 정상적인 Script도 CloudTrail Event를 기다리는 시간이 필요하다.

### 3.2 Query 파일 Encoding 결함

첫 구현은 한글 주석이 포함된 `.cwli` 파일을 AWS CLI `file://` 인수로 바로 전달했다.
Windows PowerShell 5.1과 AWS CLI의 파일 Encoding 경계에서 Query를 정상적으로 읽지
못했다.

이 문제는 공격이나 로그 수집 실패가 아니라 **조회 도구의 입력 처리 결함**이다.

### 3.3 잘못된 Scan Window

첫 구현은 Query 종료 시각을 S3 요청 직후로 고정했다. CloudTrail Event의 실제
`eventTime`은 요청 구간 안에 있었지만, CloudWatch Logs에는 몇 분 뒤 도착했다.
늦게 도착한 Log Event가 조회 범위 밖에 놓여 결과가 계속 0행이 됐다.

올바른 방식은 다음과 같다.

```text
조회 범위는 Delivery Grace만큼 넓힌다.
→ 결과는 CloudTrail event_time으로 원래 실험 구간에 다시 제한한다.
```

### 3.4 중복 구현이라는 설계 문제

Repository의 Evidence Collector에는 이미 다음 기능과 회귀 Test가 있었다.

```text
Query 주석 제거
UTF-8 no-BOM 임시 파일
Delivery Grace
event_time 재필터
최소 행 수와 제한 재시도
```

Negative Control Runner가 이를 재사용하지 않고 CWLI 실행을 별도로 구현하면서 같은
문제가 다시 발생했다. 근본 원인은 AWS 지연 자체보다 **검증된 공용 기능을 우회한
중복 구현**이었다.

---

## 4. 시간 Evidence를 해석할 때의 주의점

기존 Sanitized Record에서 확인한 값:

```text
최초 StartedAtUtc → 최종 FinishedAtUtc: 1,011초
최초 S3 읽기 구간: 약 1초
ResumeAfterRead: true
```

1,011초는 하나의 PowerShell Process가 연속 실행된 시간이라고 단정할 수 없다. 최초 S3
읽기 뒤 Query가 실패하고 Resume로 완료할 때까지의 **전체 Control Window**다. 기존
Schema에는 Resume Invocation 시작 시각이 없으므로 첫 실행과 Resume 각각의 정확한
실행시간은 확정할 수 없다.

이 한계를 해소하기 위해 새 Record는 다음을 구분한다.

```text
InvocationDurationSeconds
ControlWindowElapsedSeconds
StageDurationsSeconds.S3ReadAndValidation
StageDurationsSeconds.CloudTrailDeliveryAndQuery
StageDurationsSeconds.AlarmNonTransitionObservation
CloudTrailDeliveryAttempts
```

---

## 5. 재발 방지 변경

### 공용 CWLI 실행기 재사용

Negative Control Runner의 별도 `start-query`·`get-query-results` 구현을 제거했다.
`automation/Evidence.Collection.psm1`의 공용 함수를 사용하고, Query 조건과 재시도 값은
`automation/project.psd1`의 `capital-one-negative-control` 설정 한곳에서 관리한다.

### 전체 Deadline과 진행률

```text
S3 읽기·가짜 데이터 검증: 수초 예상
CloudTrail 전달·Query: 전체 600초 Deadline
진행률: 30초 간격 Delivery Attempt와 남은 Budget 표시
Alarm 비전환 관찰: 120초
```

600초는 CloudTrail 전달 완료를 보장하는 시간이 아니다. 사용자가 이유 없이 계속
기다리지 않도록 만든 **프로젝트 검증의 운영 상한**이다. Deadline을 넘기면 성공이나
실패로 단정하지 않고 Evidence 미완료로 중단한다.

### 중복 S3 요청 방지

같은 `ExperimentId`의 Record가 있으면 새 `GetObject`를 거부한다. S3 읽기까지 성공하고
CloudTrail 조회에서만 실패한 경우에는 정확한 Resume 확인문을 사용해 기존 Event를
다시 조회한다.

---

## 6. Terraform과의 관계

이번 장시간 대기의 원인은 Terraform Resource 구성이 아니다. Terraform Source 변경은
Capital One Alarm Description에 조사에 필요한 고정 필드를 넣는 별도 보강이다.

```text
scenario=CAPITAL-ONE
severity=HIGH
action=s3:GetObject
actor=aws-topology-primary-karpenter-node
object=validation/*
verdict=success
```

2026-08-12 Plan Snapshot에서는 Alarm Description 1개 in-place update, Create·Delete 0을
확인했다. 이 Snapshot은 변경 범위 Evidence일 뿐 재개 후 실행 대상으로 간주하지 않는다.
Apply 직전에 Fresh Plan을 다시 만들고 동일 범위인지 확인한 뒤 명시적 승인을 받아야 한다.

---

## 7. 보고서에 사용할 수 있는 주장

사용 가능:

```text
공격 Role 접근과 정상 운영자 접근을 같은 Object 기준으로 대조했다.
두 접근 모두 CloudTrail에 기록됐다.
대표 탐지 Rule은 공격 Role 접근에서 전환되고 정상 운영자 접근에서는 전환되지 않았다.
로그 전달 지연과 Event 발생 시간을 분리해 검증했다.
실패한 조회를 반복 공격·반복 접근으로 해결하지 않고 Resume 가능한 절차를 만들었다.
```

사용하면 안 됨:

```text
모든 정상 접근에서 오탐이 없다.
CloudTrail은 항상 5분 안에 도착한다.
10분 안에 Event가 없으면 공격 또는 접근이 없었다.
Refactor 이후 Runtime 재실행까지 완료했다.
Alert Description 보강이 AWS Runtime에 적용됐다.
```

마지막 두 항목은 각각 Runtime 재실행과 명시적 승인 후 Terraform Apply가 아직 없기
때문이다.

---

## 8. 최종 보고서 구성 후보

한 페이지로 줄일 때:

```text
문제: 공격만 확인하면 오탐 여부를 알 수 없음
대조 실험: 공격 Node Role vs 정상 terra-user의 같은 가짜 Object GetObject
결과: 둘 다 기록, 공격만 Alarm 전환
시행착오: Encoding·전달 지연 시간창·중복 Query 구현
개선: 공용 Collector, 600초 Deadline, 진행률, Resume, 단계별 시간 Evidence
한계: 단일 정상 Identity·단일 Object·단일 Rule 검증
```

원본 Evidence 위치와 공개 제한은
[`OBSERVABILITY-EVIDENCE-INDEX.md`](./OBSERVABILITY-EVIDENCE-INDEX.md)를 따른다.

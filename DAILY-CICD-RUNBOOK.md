# DVWA Daily CI/CD Runbook

이 문서는 개인 AWS 계정의 교육용 환경을 대상으로 한다.

## 수명주기

- `foundation/`: ECR, GitHub OIDC Provider, GitHub Actions IAM Role,
  30일 보안 로그 S3·CloudWatch 목적지, 기존 Route 53 Hosted Zone 조회와
  CloudFront ACM 인증서
  - 최초 한 번만 생성한다.
  - 평소 `daily-down.ps1`에서 삭제하지 않는다.
- 현재 Terraform Root: EKS, RDS, VPC, NAT, ALB, CloudFront 등 Daily Runtime
  - 아침에 생성하고 하원 전에 삭제한다.
- `D:\DVWA`: Source, GitHub Actions Workflow, Helm Chart, Argo CD Application

Terraform State, Plan, Deploy Private Key, Database Password는 Git이나 Vault에
넣지 않는다.

## 최초 한 번

GitHub CLI를 공식 경로로 설치하고 로그인한다.

```powershell
gh auth login
```

먼저 변경 없는 Preview를 확인한다.

```powershell
.\setup-foundation.ps1 -DomainName '<EXISTING_PUBLIC_DOMAIN>'
```

Plan과 AWS Account를 확인한 뒤에만 실행한다.

```powershell
.\setup-foundation.ps1 `
  -DomainName '<EXISTING_PUBLIC_DOMAIN>' `
  -ConfirmSetup 'SETUP FOUNDATION'
```

`-DomainName`은 기존 인증서의 의도치 않은 제거 Plan을 막기 위한 필수 입력이다.
도메인을 사용하지 않는 Foundation이라면 빈 문자열을 명시한다.

이 Script는 다음을 수행한다.

- GitHub Repository ID 기반 immutable OIDC Subject 검증
- Foundation Apply
- Argo CD read-only Deploy Key 생성·등록
- `AWS_REGION`, `ECR_REPOSITORY`, `AWS_ROLE_ARN` Repository Variable 설정·재확인

### Capital One 수집·탐지 활성화

기본 Foundation에서는 추가 S3 Data Event와 Capital One Detector가 꺼져 있다.
통제된 실습 전에는 두 기능을 함께 넣은 별도 Foundation Plan을 먼저 확인한다.

```powershell
.\setup-foundation.ps1 `
  -DomainName '<EXISTING_PUBLIC_DOMAIN>' `
  -EnableProjectS3DataEvents `
  -EnableCapitalOneDetection
```

Plan에서 다음만 추가·변경되는지 확인한다.

```text
CloudTrail Project S3 Object Data Event Selector
Capital One CloudWatch Logs Metric Filter
Capital One CloudWatch Alarm
기존 Security Alert SNS 연결
```

승인된 실습 시간에만 다음 두 확인문으로 Apply한다.

```powershell
.\setup-foundation.ps1 `
  -DomainName '<EXISTING_PUBLIC_DOMAIN>' `
  -EnableProjectS3DataEvents `
  -EnableCapitalOneDetection `
  -ConfirmCapitalOneDetection 'ENABLE CAPITAL ONE DETECTION' `
  -ConfirmSetup 'SETUP FOUNDATION'
```

Detector 조건은 다음과 같다.

```text
eventSource=s3.amazonaws.com
+ eventName=GetObject
+ Primary Karpenter Node Role
+ key=validation/*
+ errorCode 없음
→ 1분 동안 1건 이상이면 ALARM
```

Alarm은 기존 Security Alert SNS Topic으로 전달한다. CloudTrail 전달 지연이 있으므로
실행 직후 경보가 없다고 실패로 단정하지 않는다. Evidence Query는 성공뿐 아니라
복구 뒤 `AccessDenied`도 보존한다.

```powershell
.\daily-down.ps1 `
  -EvidenceOnly `
  -RunEvidenceQueries `
  -ExperimentId '<EXPERIMENT_ID>' `
  -ScenarioId 'CAPITAL-ONE' `
  -EvidenceStartUtc '<UTC_START>' `
  -EvidenceEndUtc '<UTC_END>' `
  -EvidenceDeliveryGraceMinutes 10
```

S3 Data Event와 Custom Metric은 비용이 발생할 수 있다. 실습 종료 후 두 Switch를
제외한 Foundation Plan에서 Selector·Metric Filter·Alarm 제거만 나타나는지 확인한
뒤 승인해 비활성화한다. Log Bucket·Trail·SNS·GuardDuty Detector 삭제가 보이면
적용하지 않는다.

### 기존 EKS Log Group의 일회성 소유권 이전

Observability 보강 전부터 `/aws/eks/aws-topology-primary/cluster`가 존재하고
Daily State의 아래 주소가 이를 소유한다면, Foundation 최초 Apply 전에
State 소유권을 한 번 이전해야 한다.

```text
module.primary_eks.aws_cloudwatch_log_group.this[0]
→ foundation/aws_cloudwatch_log_group.eks_primary
```

이 작업은 Log Group을 새로 만들거나 삭제하는 작업이 아니라 동일한 AWS
객체의 Terraform 소유 State만 옮기는 작업이다. 그래도 State를 변경하므로
다음 순서는 검토·승인 후에만 수행한다.

1. 양쪽 `terraform.tfstate`의 Timestamp Backup을 로컬에 만든다.
2. Foundation State에 기존 Log Group을 `terraform import`한다.
3. Foundation Plan에서 기존 Log Group이 새로 생성·삭제되지 않고
   보존기간만 관리되는지 확인한다.
4. Daily State에서 기존 Module 주소만 `terraform state rm`한다.
5. 승인된 Foundation Apply로 새 Log Group·Delivery Destination·Output을
   생성한다.
6. Daily Plan에서 해당 Log Group 삭제가 사라졌고 Foundation Output을
   정상 참조하는지 확인한다.

`daily-up.ps1`과 `daily-down.ps1`은 이 이전이 끝나기 전 해당 EKS Log
Group 삭제가 Plan에 나타나면 중단한다. State 파일은 Git·Vault·Evidence에
넣지 않는다.

### Runtime Profile 전환의 State 전제

이번 Profile 전환은 DR·Valkey·EFS Resource에 `count` 주소를 도입하므로
**Daily State가 비어 있는 상태에서만 최초 적용**한다. 기존 Daily State가 남은
환경에 Source만 교체하지 않는다. 먼저 기존 Source의 `daily-down.ps1`로 Daily
State를 0으로 만든 뒤 새 Source의 Plan을 확인한다. 다른 Account나 비어 있지
않은 State에 이 변경을 이식할 때는 별도의 State migration 검토가 필요하다.

## 아침

```powershell
.\daily-up.ps1 -RuntimeProfile minimal
```

Plan을 확인한 뒤:

```powershell
.\daily-up.ps1 -RuntimeProfile minimal -ConfirmApply 'APPLY DAILY'
```

성공 기준:

- Foundation ECR·OIDC·IAM 실재
- Foundation 보안 로그 S3·CloudWatch 목적지와 30일 보존 설정 실재
- Primary·DR EKS의 DVWA Namespace Log Forwarder 준비
- Daily Terraform Apply 및 EKS Add-on 완료
- 현재 Bastion IP로 로컬 `bas` SSH Alias 갱신
- Git에 선언된 immutable ECR Image 존재
- 전용 DVWA Database·User와 `dvwa-db` Secret 준비
- Argo CD `Synced / Healthy`
- DVWA Pod가 선언된 Image로 Ready
- CloudFront URL의 HTTP 응답 성공

### Runtime Profile

| Profile | 평상시 용도 | Primary Node | Primary RDS | DR Runtime |
|---|---|---:|---|---|
| `minimal` | 기본 수업·개발·웹 보안 실험 | 1대부터 검증 | Single-AZ | 없음 |
| `dr-test` | 장애·복구 증거 수집 | 1대부터 검증 | Single-AZ | 있음 |
| `full` | 기존 고가용성 구성 재현 | 2대 | Multi-AZ | 있음 |

Valkey와 EFS는 어느 Profile에서도 자동 활성화되지 않는다. 실제 Application 또는
실험 의존성이 증명된 경우에만 `-EnableValkey`, `-EnableEfs`로 켠다. HTTP 허용
실험은 안전 기본값인 HTTPS Redirect를 `-AllowHttp`로 명시적으로 해제한다. 활성
Daily State가 있는 동안 Profile이나 이 세 Toggle을 바꾸지 않으며, 먼저
`daily-down.ps1`로 State를 비운다.

### Security Scenario Profile

Runtime 규모와 보안 상태는 별도 입력이다.

| Profile | Primary Karpenter IMDS | Primary Node Role | DR |
|---|---|---|---|
| `hardened` | IMDSv2 필수·Hop 1 | 실습용 S3 권한 없음 | 항상 hardened |
| `capital-one-lab` | IMDSv1 허용·Hop 2 | Primary bucket의 `validation/*` 읽기만 허용 | 항상 hardened |

기본값은 `hardened`다. `capital-one-lab`은 가짜 검증 자료만 사용하는 승인된 실습
시간에 한해 사용한다. Plan을 먼저 확인한 뒤 실제 Apply에는 두 확인문이 모두
필요하다.

```powershell
.\daily-up.ps1 `
  -RuntimeProfile minimal `
  -SecurityScenarioProfile capital-one-lab

.\daily-up.ps1 `
  -RuntimeProfile minimal `
  -SecurityScenarioProfile capital-one-lab `
  -ConfirmSecurityScenario 'ENABLE CAPITAL ONE LAB' `
  -ConfirmApply 'APPLY DAILY'
```

활성 Daily State나 Session이 있는 동안 Security Scenario를 바꾸지 않는다. 먼저
`daily-down.ps1`로 Runtime을 제거하고, 새 Profile의 Fresh Plan을 검토한다. Profile
변경은 새 EC2NodeClass를 선언할 뿐 기존 Karpenter Node를 즉시 교체하지 않으므로,
실제 Node의 MetadataOptions 검증과 Node 교체는 별도 승인 절차에서 수행한다.

## Daily Session 시간 제한

`-ConfirmApply 'APPLY DAILY'`를 통과한 뒤 실제 Apply를 시작하기 전에 기본값
`-WatchdogMode On`으로 현재 사용자용 Windows Scheduled Task가 등록된다.
시간은 `daily-up.ps1` 명령을 시작한 시각부터 계산한다.

평일처럼 자동 Down이 필요 없으면 `-WatchdogMode Off`를 명시할 수 있다. 이 경우
Deadline과 Sanitized Session Log는 남지만 자동 Down Scheduled Task는 생성되지
않는다. 실행 중인 Session에서 On/Off를 바꾸지 말고 먼저 Daily Down한다.

- 5시간: Soft Deadline. 새 변경·공격·Apply를 시작하지 않고 Evidence와
  Down을 준비한다.
- 6시간: Hard Deadline. Goal 진행보다 `daily-down.ps1`을 우선한다.
- Hard Deadline에 Terraform Process나 State Lock이 있으면 Kill·강제 해제하지
  않고 15분 간격으로 최대 2시간만 재확인한다.
- Watchdog은 Fresh Destroy Plan, Foundation 보호 검사, Evidence 수집,
  Karpenter NodePool·NodeClaim 선행 정리, 잔존 Runtime 검사까지 기존
  `daily-down.ps1`에 위임한다.
- 정상적인 조기 Down과 Watchdog Down이 성공하면 예약 작업과 활성 Session
  상태가 제거된다. Sanitized Lifecycle Log와 Down 시도별 진단 Log는 로컬에
  남는다.

활성 상태와 Log 위치:

```text
%LOCALAPPDATA%\aws-topology\daily-session\active-session.json
%LOCALAPPDATA%\aws-topology\daily-session\logs\<session-id>.log
%LOCALAPPDATA%\aws-topology\daily-session\logs\<session-id>.daily-down.<attempt-id>.log
```

상태에는 선택한 Security Scenario가 함께 기록된다. 상태와 Scheduled Task 인수에는
AWS Credential, Private Key, Password, Token을 기록하지 않는다. 노트북 전원이
꺼졌거나 AWS Profile을 사용할 수
없으면 자동 Down을 보장할 수 없으므로, 다음 접속 때 실패 상태와 실제 과금
Runtime을 먼저 확인한다.

Down 진단 Log에는 Sanitized stdout/stderr, 남은 Terraform State 주소와 Project
Tag 기반 AWS Runtime이 기록된다. 한 번의 Down이 Retry 종료 시각을 넘겨 실패하면
자동 재시도는 종료되고 `RetryWindowExpired` 상태로 남으므로, 진단 Log와 실제
Runtime을 확인한 뒤 수동으로 복구한다.

## 하원 전

```powershell
.\daily-down.ps1
```

삭제 대상과 미기록 증거 경고를 확인한 뒤:

```powershell
.\daily-down.ps1 -ConfirmDestroy 'DESTROY DAILY'
```

성공 기준:

- Daily Terraform State가 비어 있음
- Destroy 전 추적한 과금 Runtime의 AWS 잔존이 없음
- Terraform Destroy 전에 Karpenter NodePool·NodeClaim과 해당 EC2가 제거됨
- Foundation ECR·Image·OIDC·CI IAM Role은 남아 있음
- Destroy 전·후 Evidence Bundle과 SHA-256 Manifest가 로컬에 남아 있음
- Daily Session Scheduled Task와 활성 상태가 제거됨

### 보안 실험 증거 수집

기본 저장 위치는
`$HOME\Documents\aws-topology-evidence\<experiment-id>\`다. 원본 AWS
Object는 임시 파일로만 내려받고, 로컬 Bundle에는 Redaction한 결과와
Object·Query Metadata를 보존한다.

Terraform을 변경하지 않고 최근 60분 로그만 수집:

```powershell
.\daily-down.ps1 `
  -EvidenceOnly `
  -ExperimentId 'login-failure-before' `
  -ScenarioId 'bank-login-failure'
```

정확한 UTC 구간을 지정:

```powershell
.\daily-down.ps1 `
  -EvidenceOnly `
  -ExperimentId 'login-failure-before' `
  -ScenarioId 'bank-login-failure' `
  -EvidenceStartUtc '2026-07-31T00:00:00Z' `
  -EvidenceEndUtc '2026-07-31T00:15:00Z'
```

팀 확정 시나리오와 별개로, 설정에 매핑한 관측 검증 후보 Query까지 같은
Evidence Bundle에 실행하려면 `-RunEvidenceQueries`를 명시한다. Query 실행은
기본값이 아니며 `ScenarioId`에 매핑된 Query가 없으면 실패한다.

```powershell
.\daily-down.ps1 `
  -EvidenceOnly `
  -RunEvidenceQueries `
  -ExperimentId 'observability-web-check' `
  -ScenarioId 'WEB-01' `
  -EvidenceStartUtc '2026-07-31T00:00:00Z' `
  -EvidenceEndUtc '2026-07-31T00:15:00Z'
```

`WEB-01`, `IAM-01`은 현재 Query·Evidence Pipeline 검증 후보이며 팀이 확정한
공격·실습 프로젝트가 아니다. 팀 시나리오가 정해지면 `automation/project.psd1`의
`ScenarioIds` 매핑을 교체하거나 필요한 Query만 재사용한다.
Destroy와 함께 실행할 때 Query는 Runtime Log Group이 사라지기 전인
`pre-destroy` Bundle에만 실행하고, `post-destroy` Bundle은 보존 계층의 수집만
수행한다.

S3의 CloudFront·ALB·VPC Flow Log는 Athena Query Pack으로 별도 검증한다.
Athena는 Glue Catalog를 변경하고 Scan 비용을 발생시키므로 Daily Down에 자동
연결하지 않는다. 먼저 승인 없이 Preview로 Account·Region·Foundation Bucket,
최대 6시간 시간창, DDL 여부와 결과 Prefix를 확인한다.

```powershell
.\observability\Invoke-AthenaQueryPack.ps1 `
  -QueryName cloudfront-trace `
  -StartUtc '2026-08-02T08:58:00Z' `
  -EndUtc '2026-08-02T09:00:00Z' `
  -CreateSchema
```

검토된 범위를 실행할 때만 정확한 확인 문구를 추가한다.

```powershell
-ConfirmRun 'RUN ATHENA QUERY PACK'
```

실행기는 임의 SQL을 받지 않고 검증된 Query 네 개만 허용한다. SQL·실행 상태·
Scan Byte·최대 1,000행 결과는 같은 `ExperimentId`의 Local Evidence에 저장하고,
이후 Collector가 Manifest와 SHA-256을 생성한다.

일반 `daily-down.ps1 -ConfirmDestroy 'DESTROY DAILY'`도 Destroy 전·후
Bundle을 자동 생성한다. 일반 모드에서는 수집 실패를 경고와 Manifest에
남기고 비용 Runtime 제거를 계속한다.

보안 실험 종료 때는 필수 Source를 명시해 Strict Mode로 실행한다.
필수 Source가 누락되면 Destroy 전에 중단한다.

```powershell
.\daily-down.ps1 `
  -ExperimentId 'login-failure-after' `
  -ScenarioId 'bank-login-failure' `
  -RequireEvidence `
  -RequiredEvidenceCollector 'dvwa-application' `
  -ConfirmDestroy 'DESTROY DAILY'
```

현재 Collector 이름은
`cloudtrail-management`, `cloudfront-access`, `alb-primary-access`,
`vpc-reject`, `eks-control-plane`, `waf-edge`, `dvwa-application`이다.
Log 전달은 지연될 수 있으므로 실험 종료 시각과 수집 구간을 기록하고,
누락 Source를 성공으로 간주하지 않는다.

## 실패 처리

- Script는 실패한 단계를 성공으로 보고하지 않는다.
- `*.tfplan`은 Git에서 제외된다. 승인을 보류했다면 다음 실행에서 새 Plan을 만든다.
- Apply/Destroy 도중 전원이 빠졌다면 Process를 강제 종료하지 말고 오류와 현재
  State를 먼저 확인한다.
- Secret, Private Key, State, Plan 내용을 채팅·Vault·GitHub Log에 붙여 넣지 않는다.

## 다른 노트북·팀 AWS 계정으로 이전

Source만 이전하고 개인 계정의 `terraform.tfstate*`, `*.tfplan`, AWS
Credential, Deploy Private Key, Bastion Private Key는 복사하지 않는다.

새 노트북에서는 Git, Terraform, AWS CLI, GitHub CLI, OpenSSH를 설치하고
다음 일회성 준비를 수행한다.

1. private `Unoh03/Uns-DVWA` Repository를 Clone한다.
2. Terraform Source를 전달받되 `.terraform/`, State, Plan은 제외한다.
3. 팀 AWS Profile과 Account ID를 확인하고, 팀 계정에 존재하는 Seoul·Tokyo
   EC2 Key Pair 이름과 Seoul Bastion Private Key 경로를 확인한다.
4. `setup-foundation.ps1`에 팀 Profile·Account를 명시해 Foundation,
   read-only Deploy Key, GitHub Variables를 새 계정 값으로 1회 생성한다.
5. 같은 Profile·Account와 EC2 Key Pair 이름·Private Key 경로를
   `daily-up.ps1`과 `daily-down.ps1`에 전달한다.

예시:

```powershell
.\setup-foundation.ps1 `
  -AwsProfile 'TEAM_PROFILE' `
  -ExpectedAccountId 'TEAM_ACCOUNT_ID' `
  -DomainName 'TEAM_EXISTING_PUBLIC_DOMAIN' `
  -RotateDeployKey `
  -ConfirmSetup 'SETUP FOUNDATION'

.\daily-up.ps1 `
  -AwsProfile 'TEAM_PROFILE' `
  -ExpectedAccountId 'TEAM_ACCOUNT_ID' `
  -PrimaryBastionKeyPairName 'TEAM_SEOUL_KEY_NAME' `
  -DrBastionKeyPairName 'TEAM_TOKYO_KEY_NAME' `
  -SshKeyPath "$HOME\.ssh\TEAM_SEOUL_KEY.pem"
```

한 Repository의 `AWS_ROLE_ARN` 등 Repository Variables는 한 시점에 한 AWS
계정만 가리킨다. 개인 계정과 팀 계정에 동시에 배포하려면 GitHub
Environments 또는 별도 Workflow 입력으로 분리하기 전까지 대상 계정을
명시적으로 전환한다.

`-RotateDeployKey`는 새 노트북에 이전 Private Key를 복사하지 않고 새 Key
Pair를 만들 때만 사용한다. 기존 GitHub Deploy Key를 교체하므로, 이전
Private Key를 쓰는 실행 중 Argo CD는 Repository 접근을 잃는다. 팀 계정
이전처럼 Runtime을 새로 만드는 시점에만 사용한다.

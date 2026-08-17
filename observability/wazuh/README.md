# Wazuh AWS 원본 로그 연결

이 폴더는 Local Docker Wazuh를 기존 AWS 로그 Source에 연결하기 위한 **설정 계약**이다.
Terraform은 AWS의 Reader Role까지만 관리하고 Wazuh Container·Credential·`ossec.conf`는
관리하지 않는다.

## 첫 연결 범위

첫 Runtime 검증은 CloudTrail 하나만 사용한다.

```text
CloudTrail
→ Foundation Security Log S3
→ Wazuh Reader Role의 임시 STS Session
→ Local Wazuh Manager
→ Wazuh Alert·Archive
```

WAF와 Primary DVWA CloudWatch Logs 읽기 권한도 같은 Reader Role에 좁게 포함되어 있지만,
CloudTrail 수집 성공 전에는 Wazuh 설정에 추가하지 않는다.

## 책임 경계

- `foundation/wazuh.tf`: 기본 비활성인 Reader Role과 Read-only Policy
- `foundation/outputs.tf`: Role ARN과 비민감 Source 이름·Region·Prefix
- `cloudtrail-ossec.example.xml`: Wazuh GUI에 넣을 첫 수집 블록
- Git 밖의 임시 Credential 파일: 이미 Reader Role을 Assume한 단기 Session

금지 사항:

- Terraform으로 `aws_iam_user`나 `aws_iam_access_key`를 만들지 않는다.
- Host의 광범위한 `terra-user` Profile 전체를 Container에 Mount하지 않는다.
- `access_key`, `secret_key`, `session_token` 값을 XML·Git·Evidence에 기록하지 않는다.
- Wazuh가 수집한 S3 원본을 삭제하지 않는다.

## GUI에 넣기 전 순서

1. `enable_wazuh_log_reader=true`와 같은 계정의 명시적 IAM Principal ARN으로 Foundation
   Plan을 검토한다.
2. 승인된 Apply 뒤 `wazuh_log_reader_role_arn`을 대상으로 임시 STS Session을 발급한다.
3. Session만 담은 `wazuh-reader` Profile을 Manager Container의
   `/root/.aws/credentials`에 Read-only로 Mount한다.
4. `cloudtrail-ossec.example.xml`의 Bucket·Account ID를
   `terraform -chdir=foundation output -json wazuh_log_sources` 값으로 치환한다.
5. Wazuh Dashboard의 `Server management → Settings`에서 기존 `<ossec_config>` 내부에
   `<wodle>` 블록을 추가하고 저장·재시작한다.

`iam_role_arn`을 XML에 함께 쓰지 않는다. 이 설계의 `wazuh-reader` Profile은 이미 Reader
Role로 발급된 Session이므로 같은 Role을 다시 Assume하게 만들면 안 된다.

## 첫 Runtime Gate

- `only_logs_after`는 **첫 실행 전에** `2026-AUG-12`로 고정한다.
- Account ID는 프로젝트 계정 하나만 지정한다.
- Region은 대표 시나리오가 실행되는 `ap-northeast-2`만 지정한다.
- Wazuh Manager 로그에서 S3 인증·권한·Parsing 오류가 없어야 한다.
- 새 CloudTrail Event가 Wazuh에 나타나야 한다.
- S3 원본 Object가 수집 뒤에도 남아 있어야 한다.
- Manager 재시작 뒤 설정과 수집 상태가 유지되어야 한다.

첫 실행 뒤 날짜를 과거로 바꿔도 이미 건너뛴 더 오래된 S3 로그는 자동으로 다시 읽히지
않는다. 과거 로그 재수집은 중복 Alert 위험이 있으므로 별도 승인된 `reparse` 절차로만
수행한다.

## Primary DVWA 저지연 Push

2026-08-17 현재 Primary DVWA 한 Source만 다음 경로가 Runtime으로 연결됐다.

```text
DVWA CloudWatch Logs
→ Subscription → Lambda 안전 Allowlist → SQS
→ Start-WazuhPushShadowBridge.ps1
→ Event별 Ledger + wazuh-push-live.jsonl
→ Wazuh localfile → Rule 100102·100103
```

Subscription은 위험 Event만 고르지 않지만 Lambda Payload는 안전 감사 필드만 남긴다.
원본 `message`·`log`, Credential, Cookie, Command 원문·응답은 Queue·로컬 파일에 저장하지
않고 SHA-256만 남긴다. 전체 원문 조사는 기존 CloudWatch·S3와 10분 Poll을 사용한다.

Bridge 시작:

```powershell
Set-Location 'D:\terraform\aws_terraform_build_code'
.\tools\Start-WazuhPushShadowBridge.ps1 `
  -ConfirmConsume 'CONSUME WAZUH PUSH'
```

Bridge는 `terra-user`를 직접 소비 권한으로 쓰지 않고, Terraform Reader Role의 최대 1시간
임시 STS Session을 Process 환경에만 넣었다가 종료 시 복구한다. 동시에 두 Bridge를 켜면
Writer Lock에서 실패한다.

무해 전송 검증:

```powershell
.\observability\wazuh\Invoke-WazuhPushValidation.ps1 `
  -ConfirmRun 'SEND WAZUH PUSH VALIDATION'
```

Rule `100102`는 `SAFE_VALIDATION_EVENT`가 Wazuh까지 도착했다는 전달 검증용 Level 3이다.
실제 `command.execution + ec2_imds`의 Push 탐지는 Rule `100103` Level 10이며 아직 Runtime
3회 검증 전이다. 최종 무해 검증 3회의 총 지연은 6.439초·3.427초·3.761초였다.

Bridge가 Live JSONL을 Flush한 직후 Ledger Rename 전에 비정상 종료되면 재전달로 한 건이
중복될 수 있다. 이는 유실보다 중복을 허용한 at-least-once 경계이며 exactly-once 주장이
아니다.

## Dashboard 미니 실습 Preflight

`Test-WazuhMiniDrill.ps1`은 Local Wazuh의 초보자용 Dashboard 실습을 시작하기 전 사용하는
읽기 전용 검사다. 필요하면 Stack을 시작하고 다음 항목을 확인한다.

- Manager·Indexer·Dashboard 3개 Service Running
- `AWS 보안관제 현황`, `AWS 보안 사건 상세`
- `[AWS-SOC]` Visualization 14개와 Saved Search 2개
- Saved Search의 안전한 6개 Field·최신순 정렬·불필요한 Exists Filter 없음
- ALB 응답 상태의 코드 오름차순 정렬
- `Last 7 days` 안의 Edge·WAF·ALB·Workload·AWS 접근과 Rule `100100` Evidence 존재

```powershell
.\observability\wazuh\Test-WazuhMiniDrill.ps1 -StartStack
```

`WAZUH_MINI_DRILL_READY=yes`가 출력돼야 보존 Event 기반 실습을 시작한다. 이 검사는 새
AWS Event를 만들거나 Wazuh 설정을 변경하지 않는다. 보존된 다섯 Source Record는 여러
날짜의 검증 실행에서 수집됐으므로 동일한 한 공격의 완전한 Timeline 증거로 사용하지
않는다.

`-BackupPath`를 지정하면 같은 `.kibana_1`용 Raw 복구 Backup과 SHA-256을 만든다. 이 파일은
동일 Local Stack의 장애 조사·복구용이며 Wazuh Dashboard UI에서 Import하는 공식 Saved
Objects Export 형식이 아니다.

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

# 3차 프로젝트 Terraform·CI/CD 인수인계

## 관련 구현 계획

S3 보안 로그 분석, Amazon Managed Grafana, EKS Pod Identity 및 Log Source 분리의 정확한 요구사항·Terraform 계약·Runtime 검증·Codex 첫 실행 범위는 다음 문서를 기준으로 한다.

- [`OBSERVABILITY-IAM-IMPLEMENTATION-PLAN.md`](./OBSERVABILITY-IAM-IMPLEMENTATION-PLAN.md)

해당 문서는 Source 존재와 실제 Runtime 완료를 구분하며, 이후 구현에서 이 문서의 Stop Gate와 Definition of Done을 우선 적용한다.

## 현재 판정

> 이 Source는 장운호 개인 AWS Account에서 검증 중인 작업본이다.
> 수현 씨 Account에서 바로 `terraform apply`하지 않는다.

- 개인 Account: `433048100798`
- Region: Primary `ap-northeast-2`, DR `ap-northeast-1`
- Application Repository: private `Unoh03/Uns-DVWA`
- 2026-07-30 확인:
  - Foundation의 ECR·GitHub OIDC·CI IAM Role 생성 성공
  - GitHub Actions가 OIDC로 ECR Image를 Build·Push하고 GitOps Commit 생성 성공
  - Daily Terraform에서 249개 Runtime Resource 생성 성공
- 아직 진행 중:
  - Argo CD `Synced/Healthy`
  - DVWA Pod와 자동 Database 초기화
  - 완전한 Cold Start 재현
  - 수현 씨 Account 이식

## 전달본에 포함하지 않는 것

다음은 Account·Credential·Local State 경계이므로 Source ZIP에서 제외한다.

- `.terraform/`
- `terraform.tfstate*`
- `*.tfplan`, `tfplan`
- `*.tfvars`
- `.env*`
- `*.pem`, `*.key`, `*.pfx`, `*.p12`
- kubeconfig와 기존 ZIP

개인 State나 `terraform.tfvars`를 복사하지 않는다. 수현 씨 환경에서는 새
State와 새 입력값으로 시작한다.

## 수현 씨 환경에서 반드시 바꿀 값

### PowerShell Script 기본값

다음 파일에는 장운호 개인 환경 기본값이 남아 있다.

- `setup-foundation.ps1`
  - `ExpectedAccountId`
  - `GitHubRepository`
  - `ArgoDeployKeyPath`
- `daily-up.ps1`
  - `ExpectedAccountId`
  - `GitHubRepository`
  - `PrimaryBastionKeyPairName`
  - `SshKeyPath`
  - `ArgoDeployKeyPath`
- `daily-down.ps1`
  - `ExpectedAccountId`
  - `PrimaryBastionKeyPairName`

현재는 Parameter로 덮어쓸 수 있지만, 팀 전달 전 팀 기본값 또는 별도
Configuration 파일로 정리하는 편이 안전하다.

### Terraform 입력

수현 씨 Account 기준으로 새 `terraform.tfvars`를 작성한다.

- Primary·DR Bastion EC2 Key Pair 이름
- Domain과 Route 53 Zone 소유 방식
- DR 활성화 여부
- Project Name·Region·CIDR 등 환경별 값

로컬에 PEM 파일을 내려받는 것만으로 AWS EC2 Key Pair가 생성되지는 않는다.
각 Region의 AWS Account에 같은 이름의 Key Pair가 실제로 있어야 한다.

### GitHub·Foundation

- `gh auth status`로 수현 씨가 관리할 GitHub Account·Repository를 확인한다.
- private Repository를 유지한다.
- Repository마다 read-only Argo CD Deploy Key를 별도로 등록한다.
- GitHub Repository Variables:
  - `AWS_REGION`
  - `ECR_REPOSITORY`
  - `AWS_ROLE_ARN`
- GitHub Actions OIDC Trust의 `sub`는 실제
  `repo:<owner>/<repo>:ref:refs/heads/main`과 정확히 일치해야 한다.
- 장기 AWS Access Key를 GitHub Secret에 넣지 않는다.

## Terraform State 소유권

두 Root는 서로 다른 State를 사용한다.

- `foundation/`
  - ECR Repository와 Lifecycle Policy
  - GitHub Actions OIDC Provider
  - GitHub Actions IAM Role
  - 일상적인 `daily-down.ps1`에서 삭제하지 않음
- Repository Root
  - VPC·EKS·Node·RDS·Bastion·Argo CD 등 Daily Runtime
  - `daily-down.ps1`의 삭제 대상

현재 Local State 방식은 개인 Account 검증용이다. 여러 팀원이 같은 Account에
동시에 Apply하기 전에 Remote Backend와 State Locking을 별도 설계해야 한다.

## 현재 발견된 결함과 보정

1. MariaDB 11.8 계열은 `require_secure_transport=ON`이 기본이다.
   - 비암호화 bootstrap이 `ERROR 3159`로 실패했다.
   - RDS Global CA Bundle과 TLS 연결을 사용하도록 수정했다.
   - 개인 Account Runtime 재검증은 아직 진행 중이다.
2. 현재 Argo CD CRD가 `spec.syncPolicy.retry.refresh`를 거부했다.
   - 해당 비지원 필드를 제거했다.
3. Windows Secret 임시파일 ACL이 잘못된 Account 문자열을 부여했다.
   - 현재 Windows Identity 전체 이름을 사용하도록 수정했다.
4. EKS Managed Node Group `release_version`이 자동 변경되면 Daily Apply 중
   예상하지 않은 Rolling Update가 발생해 시간이 크게 늘어난다.
   - 팀 전달 전에 Version Pinning 또는 의도적인 Upgrade 절차를 결정한다.
5. SSM Association 대기 Loop는 일시 오류를 오래 재시도한다.
   - 인증 오류와 단순 Pending을 구분하도록 후속 보정이 필요하다.

## 수현 씨 Account 적용 전 권장 순서

1. 개인 Account의 현재 업 검증을 완료한다.
2. 위 하드코딩을 팀 입력으로 분리한다.
3. 새 `terraform.tfvars`와 Account·Region·Key Pair·Domain을 검토한다.
4. `terraform fmt -check`와 `terraform validate`를 실행한다.
5. `foundation/` Plan을 먼저 검토하고 최초 1회 Apply한다.
6. GitHub OIDC Build·ECR Push를 EKS 없이 검증한다.
7. Daily Root Plan의 생성·변경·삭제 수와 예상 비용을 검토한다.
8. Daily Apply 후 Argo CD·DVWA·Database를 검증한다.

## 사용자가 원하는 최종 경험

```text
Source Push
→ GitHub Actions OIDC
→ ECR immutable Image
→ GitOps Commit
→ Argo CD
→ EKS의 DVWA 자동 갱신

daily-up.ps1
→ Daily Runtime 생성
→ Private Repository·Database·Argo CD 자동 복구
→ DVWA Ready

daily-down.ps1
→ 과금 Daily Runtime 제거
→ ECR·OIDC·CI IAM·GitHub 설정은 보존
```

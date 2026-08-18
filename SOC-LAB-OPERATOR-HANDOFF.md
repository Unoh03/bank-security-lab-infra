# SOC Lab 운영 인계 — 사용자가 해야 하는 일만

이 문서는 구현 설명서가 아니라, Cloud 계정과 실제 쓰기 권한 때문에 자동으로 넘을 수
없는 경계만 모은 실행 순서다. 소스 파일 존재나 정적 Test 성공은 E2E 완료가 아니다.

## 2026-08-18 취침 전 인계 상태

- 로컬 Source·정적 계약: `SOC_STATIC_READY=true`
- Shuffle Private App 두 개: 단위 Test 후 ZIP·SHA-256 Manifest 생성 완료
- Wazuh 로컬 비밀번호 3개와 Webhook Header 난수: DPAPI CurrentUser 보호 저장 완료
- Bundle Manifest:
  `C:\Users\Unoh\Documents\aws-topology-evidence\shuffle-packages\shuffle-soc-app-bundle-20260817T211932Z.json`
- Validator ZIP SHA-256:
  `be7eb1f9a5f4c6662b253c086083660a1cd50ae9120ff774efd2e8ed0f61c6d8`
- Dispatcher ZIP SHA-256:
  `e767a948c2890fd0dbb14be59755f6853607870aec5a0252eb856ac9d8eabc98`
- 이 새 Dispatcher는 GitHub Dispatch 요청에 `return_run_details=true`를 고정해,
  수락된 Workflow Run ID와 URL을 HTTP 200 응답으로 받도록 구현됐다. 실제 GitHub Runtime
  응답은 첫 Production Dispatch에서 검증한다. 이전 Bundle은 쓰지 않는다.
- 2026-08-18 GitHub read-only 확인: `Unoh03/Uns-DVWA`는 Private·기본 Branch `main`이며,
  Repository 기본 `GITHUB_TOKEN` 권한은 `read`다. 이는 기본값이고, 두 전환 Workflow는
  각 Workflow에만 `permissions: contents: write`를 명시한다. Private Free Plan에서는 Branch
  Protection API가 기능 미지원으로 403을 반환했다. 실제 Push 권한은 첫 Workflow Runtime에서
  최종 검증한다.
- 아직 하지 않은 것: DVWA 변경 커밋·푸시, Shuffle 공개 ID/DPAPI Secret 설정,
  App Upload, Workflow 조립, Gate B5, PAT Authentication, AWS Apply, 실제 공격/E2E/Reset
- 따라서 현재 상태는 **설치 직전 Source 준비 완료**이지 Runtime 완료가 아니다.

정적 회귀검증 결과:

- SOC PowerShell Test `22/22` 통과(ACL 두 건은 실제 Windows 권한 환경에서 재검증)
- Terraform SOC Python Test `33/33`, DVWA Python Test `11/11` 통과
- DVWA PHP Audit self-test 통과
- Terraform root/Foundation `validate`, 전체 `fmt -check` 통과
- PowerShell `90`개 Parser Error `0`
- 변경 Source Secret Scan: Terraform `77`개·DVWA `7`개, Finding `0`
- 새 Bundle의 두 ZIP은 Manifest SHA-256과 재계산값이 모두 일치

이 결과는 로컬 계약과 실패 차단을 증명하지만 Shuffle Cloud와 실제 E2E 성공을 대신하지 않는다.

## 먼저 현재 상태 확인

아래 명령은 AWS, GitHub, Shuffle, Docker를 변경하지 않고 로컬 준비 상태만 보여준다.
`dvwa-local-scope`는 예상한 일곱 파일과 생성 캐시 외의 변경이 섞이면 READY를 거부한다.

```powershell
Set-Location 'D:\terraform\aws_terraform_build_code'
.\tools\Test-SocLabReadiness.ps1
```

Cloud 설정을 마친 뒤에는 read-only Export 검증까지 포함한다.

```powershell
.\tools\Test-SocLabReadiness.ps1 -Online
```

## 사용자만 할 수 있는 최초 1회 작업

1. `D:\DVWA`의 변경을 검토하고 커밋·푸시한다. 의도된 대상은 다음 일곱 파일이다.
   Runtime:
   - `.github/workflows/soc-contain-dvwa.yml`
   - `.github/workflows/soc-reset-dvwa.yml`
   - `.github/scripts/update-dvwa-security-level.py`
   - `dvwa/includes/dvwaAudit.inc.php`
   검증:
   - `tests/test_audit_log.php`
   - `tests/test_soc_security_level_transition.py`
   - `tests/test_soc_workflow_contract.py`
   `__pycache__`, `.pytest_cache`, `*.pyc`는 생성 캐시이므로 포함하지 않는다.
   변경 대상은 아니지만 `deploy/dvwa/values.yaml`도 로컬과 원격 `main`이 모두
   `defaultSecurityLevel: low`인지 확인한다.
2. 기존 `DVWA CI to ECR and GitOps`가 끝나고, 추가된 두 Workflow가 GitHub에서
   Active이며 Argo CD가 새 이미지·`defaultSecurityLevel: low` 상태로 안정화됐는지
   확인한다. 이 단계 전에는 Shuffle Production Dispatch를 연결하지 않는다.
   최초 커밋은 새 Audit 코드를 포함하므로 이미지 CI가 한 번 실행된다. 이후
   containment/reset 커밋은 `deploy/dvwa/values.yaml`만 변경하며 기존 CI의
   `paths-ignore` 대상이므로 이미지를 다시 만들지 않고 Argo GitOps 동기화만 일으킨다.
3. Shuffle Cloud에 로그인한다.
4. Private Workflow `CAPITAL-ONE-SOC-CONTAINMENT-v1`과 Webhook 하나를 만든다.
5. Webhook Trigger의 Required Header 이름을 `X-SOC-Webhook-Key`로 정하고, 다음 명령이
   잠시 복사한 값을 그 Header 값에만 붙여 넣는다. 콘솔에는 값이 나오지 않으며 Windows
   Clipboard History·Cloud Clipboard 제외 형식을 함께 넣고, 120초 뒤 아직 같은 값일
   때만 비운다. 이 명령은 사용자가 붙여 넣을 준비가 됐을 때만 실행한다.

```powershell
.\tools\Copy-SocLabWebhookHeader.ps1 `
  -ConfirmCopy 'COPY SOC HEADER TO CLIPBOARD'
```

6. Organization·Workflow·Webhook ID를 다음 명령에 넣는다.

```powershell
.\tools\Set-SocLabConfiguration.ps1 `
  -ShuffleOrgId '<ORG_UUID>' `
  -ShuffleWorkflowId '<WORKFLOW_UUID>' `
  -ShuffleWebhookId '<WEBHOOK_UUID>' `
  -ShuffleApiBase '<현재 Shuffle Cloud 계정의 HTTPS Origin>' `
  -ConfirmWrite 'WRITE SOC LAB CONFIG'
```

`ShuffleApiBase`에는 현재 로그인한 Shuffle Cloud 지역의 Origin만 넣는다. 예를 들어
`https://uk.shuffler.io/` 또는 `https://frankfurt.shuffler.io/`이며 `/api/v1` 경로는 붙이지
않는다. Shuffle의 `/admin` 지역 표시와 현재 브라우저 Host를 대조한다.

7. Shuffle API Key와 Webhook URL을 각 보안 입력창에만 넣는다. 로컬 Wazuh 비밀번호와
   Webhook Header 난수는 이미 DPAPI CurrentUser로 보호 저장돼 있으므로 다시 만들지 않는다.

```powershell
.\tools\Set-SocLabExternalSecret.ps1 `
  -Name shuffle_api_key `
  -ConfirmStore 'STORE SOC EXTERNAL SECRET'

.\tools\Set-SocLabExternalSecret.ps1 `
  -Name shuffle_webhook_url `
  -ConfirmStore 'STORE SOC EXTERNAL SECRET'
```

8. 이미 만든 Manifest를 사용해 검토된 Private App 두 개를 Shuffle 조직에 Upload한다.

```powershell
.\tools\Install-ShuffleSocAppBundle.ps1 `
  -ManifestPath 'C:\Users\Unoh\Documents\aws-topology-evidence\shuffle-packages\shuffle-soc-app-bundle-20260817T211932Z.json' `
  -ConfirmUpload 'UPLOAD SHUFFLE SOC APPS'
```

App Source를 수정했다면 기존 ZIP을 Upload하지 말고 `Build-ShuffleSocAppBundle.ps1`로
다시 만들고 새 Manifest를 사용한다.

9. [SHUFFLE-CLOUD-SETUP.md](observability/shuffle/SHUFFLE-CLOUD-SETUP.md)의 Label·분기·고정값대로 Gate B5
   Stub Workflow를 만든다. 화면상 모양이 아니라 Export 검증을 기준으로 한다.
10. 안전한 동시 10회 Gate B5 실행을 승인한다. 이 단계에는 GitHub Token과 실제 GitHub
   호출이 없다.
11. Gate B5가 `신규 1·중복 9·Stub 1·GitHub 0`으로 통과한 뒤에만 GitHub
   Fine-grained PAT을 만든다.
   - Repository: `Unoh03/Uns-DVWA` 하나
   - Repository permission: `Actions: write`
   - `Contents: write` 없음
12. PAT을 `AWS Topology SOC GitHub Dispatcher` App Authentication의
    `github_token`에 입력한다. Workflow Parameter나 Header에 붙이지 않는다.
13. Stub Action을 `dispatch_containment`로 교체하고 그 Authentication을 선택한다.
14. `gh` CLI가 설치돼 있고 `gh auth status`가 `Unoh03/Uns-DVWA`를 읽을 수 있는 계정인지
    확인한 뒤 `.\tools\Test-SocLabReadiness.ps1 -Online`이 `SOC_CLOUD_READY=true`인지 확인한다.
    이 Online 검사는 화면에 App이 보이는지만 확인하지 않는다. 현재 Workflow의 App ID를
    Upload Evidence와 Cloud App 목록에 대조하고, Dispatcher Authentication이 같은
    Organization에서 Active·Encrypted이며 정확한 App과 `github_token` Key에 연결됐는지
    확인한다. 검증 코드는 Authentication의 Value를 판정·출력·Evidence 저장에 사용하지
    않고 Key 이름만 사용하며 HTTP verbose/debug trace를 켜지 않는다. 다만 Shuffle 공식
    API에는 metadata-only Authentication endpoint가 없으므로, 목록 응답 자체가 Value를
    포함해 Process Memory에 도착하지 않는다고는 보증하지 않는다.

Gate B5의 실제 실행 명령은 다음 하나다. 이 명령은 Stub 단계에서만 허용되며 실제
GitHub 호출 Action이 보이면 실행 전에 중단한다.

```powershell
.\observability\scenarios\Test-ShuffleSocGateB5.ps1 `
  -ConfirmRun 'RUN SHUFFLE GATE B5'
```

## 매 촬영 TAKE에서 사용자가 승인할 것

다음은 실제 비용·공격·외부 쓰기가 있으므로 자동 승인하지 않는다.

1. `daily-up`의 AWS Apply와 `capital-one-lab` 활성화
2. 가짜 Training Object 준비
3. `Start-SocLab -ResponseMode contain` 실행
4. 실제 Command Injection 공격과 E2E 실행
5. Shuffle의 GitHub Workflow Dispatch
6. 필요 시 별도 수동 Reset Workflow
7. 종료 후 AWS Destroy

Cloud 최초 설정이 끝난 뒤 한 TAKE의 명령 순서는 다음과 같다. 각 명령의 Preview와
Plan을 먼저 보고, 실제 비용·공격·외부 쓰기 승인은 사용자가 그 자리에서 결정한다.

```powershell
Set-Location 'D:\terraform\aws_terraform_build_code'

.\daily-up.ps1 `
  -RuntimeProfile minimal `
  -SecurityScenarioProfile capital-one-lab `
  -WatchdogMode On `
  -ConfirmSecurityScenario 'ENABLE CAPITAL ONE LAB' `
  -ConfirmApply 'APPLY DAILY'

.\observability\scenarios\Prepare-CapitalOneDemoData.ps1 `
  -ConfirmRun 'PREPARE CAPITAL ONE DATA'

# 최초 완료 판정에서 한 번만: 3개의 독립 observe-only TAKE
.\observability\scenarios\Invoke-SocRule100103ThreeTakeRehearsal.ps1 `
  -ConfirmRun 'RUN RULE 100103 THREE TAKE REHEARSAL'

.\tools\Start-SocLab.ps1 `
  -ResponseMode contain `
  -ConfirmStart 'START SOC LAB'

.\observability\scenarios\Invoke-CapitalOneSocE2E.ps1 `
  -ConfirmRun 'RUN CAPITAL ONE SOC E2E'

.\observability\scenarios\Invoke-SocLabReset.ps1 `
  -ConfirmReset 'RESET SOC LAB TO LOW'

.\tools\Stop-SocLab.ps1 `
  -StopWazuh `
  -ConfirmStop 'STOP SOC LAB'

.\daily-down.ps1 -ConfirmDestroy 'DESTROY DAILY'
```

Reset 성공은 `low`와 새 Pod만 뜻하지 않는다. Script는 이번 TAKE의 Alarm History에서
`ALARM → OK` 자연 복귀와 현재 `OK`, 공격 Process의 임시 AWS Credential 정리 Evidence,
현재 Reset Process의 Credential 환경변수 잔존 없음까지 확인한다. `SetAlarmState`는 쓰지
않는다. 기본 대기 한도는 900초이며 결과는 `reset-retake-ready.json`과 `09-reset.json`에
민감정보 없이 남는다.

Reset은 기존 TAKE를 `CLOSED`로 만들 뿐 새 TAKE를 자동 발급하지 않는다. 촬영을 다시
시작할 때는 위 순서대로 `Stop-SocLab -StopWazuh`로 기존 Runtime을 정리한 뒤
`Start-SocLab -ResponseMode contain`을 다시 실행해 새 TAKE를 받는다.

최종 성공은 다음 한 줄 전체가 실제 Evidence로 이어질 때만 선언한다.

```text
READY → Rule 100103 → Shuffle fresh 1 / duplicate 1 → GitHub exactly 1
→ exact Commit SHA → Argo Synced·Healthy·new Pod → reattack blocked
→ normal function preserved → manual reset verified
```

재공격 차단 직후 성공 처리하지 않는다. 동일 TAKE의 Rule 100103이 기존 2개,
Shuffle Outcome이 기존 2개, GitHub containment Run이 기존 1개로 최소 120초 동안
유지되고 숫자 IP Ping까지 성공한 뒤에만 재공격 검증을 통과한다. 최종 Manifest와
Secret Scan 범위는 `source/client`의 공격 원본 요약을 포함한 TAKE 전체다.

Reset 도중 명령창이 닫혀도 같은 명령을 다시 실행하면 마지막으로 검증된 단계부터
기존 GitHub Run·Commit·Argo Evidence를 재검증해 재사용한다. 배타적 TAKE Lock이 동시
Reset을 막고, 상태 Journal이 Active TAKE와 Session 중 한쪽만 갱신된 중단을 복구한다.
같은 TAKE의 Reset Workflow를 자동으로 두 번 호출하지 않는다. 반대로 기존 Run이
확인되지 않는 애매한 Dispatch Intent는 자동 재전송하지 않고 중단한다. 실제 GitHub에서
동일 TAKE Run이 없음을 확인한 경우에만 다음과 같이 명시 재시도한다.

```powershell
.\observability\scenarios\Invoke-SocLabReset.ps1 `
  -ConfirmRetryUndispatched 'RETRY UNDISPATCHED RESET' `
  -ConfirmReset 'RESET SOC LAB TO LOW'
```

`Stop-SocLab`도 같은 TAKE Lock을 획득하고 Session·TAKE 상태 일치와 Reset Journal 부재를
확인한다. 진행 중인 containment/Reset에서는 `Stop-SocLab -StopWazuh`가 복구 상태 삭제를
거부한다.
E2E 일반 오류는 `E2E_FAILED`로 닫히지만, 공격 중 PowerShell Process 자체를 강제 종료해
중간 상태만 남긴 경우는 공격 일부 실행 여부가 모호하므로 자동 재개를 보증하지 않는다.
그때는 다시 공격하거나 Runtime 파일을 지우지 말고 Evidence와 원격 Shuffle·GitHub 상태를
먼저 확인한다.

## 보증 경계

- 지금 미리 보증 가능한 것: 소스 계약, 안전장치, 단위·정적 Test, 패키지 구조,
  실패 시 중단 조건, Evidence 형식.
- Cloud 값 입력 후 확인 가능한 것: 실제 Workflow Export, Header 인증, Gate B5 원자성,
  Upload한 App ID와 현재 Workflow Binding, Dispatcher Authentication 상태·소속 연결.
- 실제 E2E 뒤에만 확인 가능한 것: 공격 탐지 지연, GitHub 정확히 1회, Argo 배포,
  재공격 차단, 정상 기능 유지, Reset.
- 비정상 종료 경계: Reset은 단계별 재개를 지원하지만, 공격 도중 Process 강제 종료까지
  범용 자동 복구하는 상태머신은 이번 Goal 범위가 아니다.
- 제한: Shuffle App 목록의 Cloud Hash와 로컬 ZIP SHA-256은 같은 Hash가 아니다. 따라서
  읽기 검증만으로 Cloud Source의 byte-for-byte 동일성을 보증하지 않고, 고정 App ID·이름·
  버전·Workflow Binding과 실제 Gate/E2E 동작을 함께 Evidence로 삼는다.
- 제한: Shuffle Authentication 목록은 secret-bearing 응답으로 취급한다. 검증기는 Value를
  사용·출력·저장하지 않지만, 공식 metadata-only endpoint가 없어 네트워크 수신 자체까지
  배제하지는 못한다.

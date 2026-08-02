# Daily Automation extension contract

`daily-up.ps1` and `daily-down.ps1` are entry points. Project-specific facts live
in `project.psd1`; reusable orchestration and evidence collection live in
`Daily.Automation.psm1`.

## Change boundary

- A Terraform-only service normally requires no PowerShell change.
- A new application that follows the existing GitHub Actions, Argo CD, and
  health-check contract is added to `Applications`.
- A new evidence source that matches an existing collector type is added to
  `Evidence.Collectors`.
- A genuinely new bootstrap, collector, or verification protocol requires one
  new typed implementation. Do not add service-specific commands directly to
  `daily-up.ps1` or `daily-down.ps1`.

`project.psd1` must not contain credentials, private keys, database values,
Terraform state, or kubeconfig content.

The current application runner implements the `MariaDbDvwa` database contract.
Adding another application with the same deployment contract is declarative;
adding PostgreSQL, a queue, or a different bootstrap protocol requires a new
typed handler and its focused test rather than another inline branch in the
entry-point scripts.

## Evidence failure policy

- `Stop`: the source belongs to Daily Runtime and will disappear during
  destroy. Collection failure blocks destroy.
- `Warn`: the source is in Persistent Foundation and remains available for the
  configured retention period. Destroy may continue, and collection can be
  retried within that period.

`daily-down.ps1` collects before destroy and once again after Terraform state
becomes empty. The first pass protects disappearing Daily evidence; the second
copies persistent CloudTrail objects delivered during the long teardown.

Raw evidence stays outside the Terraform source tree. GitHub receives only
sanitized reports, not raw CloudTrail or application logs.

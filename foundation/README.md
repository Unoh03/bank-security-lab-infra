# Persistent CI foundation

This Terraform root owns resources that must survive the daily lab
`destroy/apply` cycle:

- GitHub Actions OIDC provider
- least-privilege GitHub Actions IAM role
- application ECR repository and lifecycle policy
- dedicated CloudTrail security-log archive
- 30-day S3 and CloudWatch log retention
- Primary GuardDuty detector with optional protection plans disabled
- GuardDuty Finding delivery to persistent CloudWatch Logs and the existing SNS alert topic

It has a separate local state and is not called by `daily-down.ps1`.
The persistent resources also use `prevent_destroy` as a second guard.

The security archive is deliberately separate from Daily application buckets.
Do not place application data under the security archive or apply its 30-day
retention rule to application storage. GuardDuty F2 is a minimal Finding route,
not Security Hub, Detective, OpenSearch, Runtime Monitoring, or a complete SIEM.

Initial setup:

```powershell
terraform -chdir=foundation init
terraform -chdir=foundation validate
terraform -chdir=foundation plan -out=foundation.tfplan
terraform -chdir=foundation apply foundation.tfplan
```

Do not store state, saved plans, credentials, or private deploy keys in Git or
the Obsidian Vault.

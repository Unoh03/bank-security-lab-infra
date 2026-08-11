# 인프라 개념 집합 축약 원장

> 목적: Terraform의 124개 `resource` 블록을 멘토 설명용 구조로 축약하되, 서비스 집합·역할별 인스턴스·구현 부품의 계층을 보존한다.

## 최종 결론

- **집합은 평평한 아이콘 하나가 아니다.** 한 서비스 가족 안에 Primary/DR 또는 App/Log처럼 역할이 다른 하위 노드를 둘 수 있다.
- 최종 전체도는 **서비스 가족 21개**, 그 안의 **역할별 노드 28개**, 그리고 **Primary/DR VPC 경계 2개**를 사용한다.
- Terraform 구현 부품만 숨긴다: Listener, Target Group, SG rule, IAM attachment, Mount Target, Subnet Group, Validation, Lifecycle 등.
- 로그 다이어그램이 이미 상세히 설명하는 로그 생성·전달·저장·탐지 내부선은 전체도에서 반복하지 않는다.
- `random_password` 2개는 AWS 인프라 노드가 아니므로 원장에만 남긴다.

## 계층 모델

```text
서비스 가족
├─ 역할별 하위 노드       ← 전체 인프라 다이어그램에 표시
└─ Terraform 구현 부품    ← 배지·경계 주석·연결 라벨 또는 생략
```

예: `RDS`는 서비스 가족 하나지만 `Primary RDS`와 `DR Read Replica`라는 두 역할 노드를 갖는다.

## 최종 서비스 가족과 역할 노드

| 서비스 가족 | 역할 노드/경계 | 귀속 리소스 | 전체도에 남길 것 | 상세 위임·숨김 |
|---|---:|---:|---|---|
| VPC / Network | 경계 2 | 11 | Primary VPC와 DR VPC를 별도 경계로 표시 | SG rule은 경계 주석, Flow Logs는 로그 다이어그램으로 위임 |
| Amazon Route 53 | 1 | 2 | DNS 진입점 | ACM과 분리 |
| AWS Certificate Manager | 1 | 2 | CloudFront TLS 인증서 | DNS validation은 내부 구성 |
| Amazon CloudFront | 1 | 4 | Edge distribution | Access-log 상세는 로그 다이어그램 |
| AWS WAF | 1 | 2 | Web ACL | Logging 상세는 로그 다이어그램 |
| Application Load Balancer | 2 | 6 | Primary ALB + DR ALB | Listener·Target Group은 내부 구성, TGB는 연결 라벨 |
| Amazon EKS | 2 | 10 | Primary EKS + DR EKS | Karpenter·LBC·ExternalDNS는 내부 chip |
| Amazon ECR | 1 | 2 | Application image repository | GitHub Actions → ECR → Argo CD/EKS 관계 유지 |
| Bastion EC2 | 2 | 2 | Primary Bastion + DR Bastion | IAM·SG는 관계와 경계로 분리 |
| AWS Systems Manager | 1 | 4 | 두 Region의 addon/bootstrap 운영 경로 | Document·Association은 내부 구성 |
| AWS IAM | 1 | 29 | CI/CD·Bastion·CloudTrail·GuardDuty·Storage 권한 중심 | Role·Policy·Attachment·Profile·OIDC는 관계 묶음 |
| EKS Pod Identity | 1 | 4 | Controller·Log Forwarder·Web S3의 Pod→AWS 권한 연결 | IAM과 별도 요소 |
| Amazon RDS | 2 | 4 | Primary RDS + DR Read Replica | Multi-AZ·KMS는 배지, replica는 연결 |
| Amazon ElastiCache / Valkey | 2 | 4 | Primary Valkey + DR Valkey | 선택 기능으로 점선, subnet group은 숨김 |
| Amazon EFS | 2 | 4 | Primary EFS + DR EFS | 선택 기능으로 점선, mount target은 숨김 |
| Amazon S3 | 3 | 15 | Application Primary + Application DR + Security Logs | Versioning·Encryption·PAB는 배지, replication은 연결 |
| Amazon CloudWatch | 1 | 9 | Logs + Metric Filter/Alarm | Source별 상세 흐름은 로그 다이어그램 |
| AWS CloudTrail | 1 | 1 | AWS API audit source | S3·CloudWatch 전달 상세는 로그 다이어그램 |
| Amazon GuardDuty | 1 | 2 | Threat detection | Event routing과 분리 |
| Amazon EventBridge | 1 | 3 | GuardDuty Finding routing | CloudWatch·SNS target 상세는 로그 다이어그램 |
| Amazon SNS | 1 | 2 | Security alert notification | Subscription은 내부 구성 |
| Terraform Local Material | 0 | 2 | 표시하지 않음 | random_password는 원장에만 보존 |
| **합계** | **역할 노드 28 + VPC 경계 2** | **124** | **서비스 가족 21개** | **미귀속 0** |

## 최종 전체도의 실제 역할 노드 28개

| 영역 | 역할 노드 |
|---|---|
| Global Edge | Route 53, ACM, CloudFront, WAF |
| Runtime | Primary ALB, DR ALB, Primary EKS, DR EKS |
| Delivery & Operations | ECR, Primary Bastion, DR Bastion, Systems Manager |
| Identity | IAM, EKS Pod Identity |
| Data | Primary RDS, DR Read Replica, Primary Valkey, DR Valkey, Primary EFS, DR EFS |
| Storage | Application S3 Primary, Application S3 DR, Security Log S3 |
| Observability & Detection | CloudWatch, CloudTrail, GuardDuty, EventBridge, SNS |

> Primary/DR VPC는 아이콘이 아니라 두 개의 구조 경계다. Karpenter·LBC·ExternalDNS는 EKS 내부 chip이며 역할 노드 수에 포함하지 않는다.

## 로그 다이어그램과의 책임 분리

| 전체 인프라에서 유지 | 로그 다이어그램에 상세 위임 |
|---|---|
| CloudFront·WAF·ALB의 요청 경로와 배치 | 각 Access/WAF Log의 생성·전달 |
| CloudWatch·CloudTrail·GuardDuty·EventBridge·SNS 서비스 노드 | Log Group, Metric Filter, Alarm, Finding routing |
| Security Log S3의 존재와 역할 | Source별 S3 Prefix, Athena, Evidence 흐름 |
| RDS Primary/DR·Valkey·EFS·Application S3/DR | 로그 다이어그램이 다루지 않으므로 전체도에서 상세 유지 |
| ECR·Bastion·SSM·IAM·Pod Identity·ACM | 로그 다이어그램이 다루지 않으므로 전체도에서 관계 유지 |

## Terraform 밖이지만 전체도에 필요한 문맥 노드

| 문맥 노드 | 이유 | 확인 근거 |
|---|---|---|
| GitHub Actions | 이미지 Build/Push 시작점 | `D:/DVWA/.github/workflows/dvwa-ecr-gitops.yml` |
| Argo CD | ECR image tag가 반영된 GitOps 배포 | `D:/DVWA/gitops/argocd/dvwa.yaml` |
| Local Docker Grafana | 현재 Dashboard 시각화 경계 | `OBSERVABILITY-IAM-DECISIONS.md` |
| WAF Live Viewer | 근실시간 WAF Event Feed | `tools/Start-WafLiveViewer.ps1` |
| 사용자·공격자·운영자 | Request·운영 행위의 Trigger | 로그 흐름 문서 |

## Module 문맥 — 124개 리소스 수에는 미포함

| Module | Source | 귀속 서비스 가족 |
|---|---|---|
| `module.primary_aws_lb_controller_pod_identity` | `cluster-controllers.tf:1` | EKS Pod Identity |
| `module.dr_aws_lb_controller_pod_identity` | `cluster-controllers.tf:18` | EKS Pod Identity |
| `module.primary_external_dns_pod_identity` | `cluster-controllers.tf:94` | EKS Pod Identity |
| `module.dr_external_dns_pod_identity` | `cluster-controllers.tf:115` | EKS Pod Identity |
| `module.primary_eks` | `eks.tf:1` | Amazon EKS |
| `module.dr_eks` | `eks.tf:72` | Amazon EKS |
| `module.primary_karpenter` | `eks.tf:144` | Amazon EKS |
| `module.dr_karpenter` | `eks.tf:156` | Amazon EKS |
| `module.primary_vpc` | `main.tf:135` | VPC / Network |
| `module.dr_vpc` | `main.tf:165` | VPC / Network |

## 124개 리소스 전수 귀속

| # | Terraform resource | Source | 서비스 가족 | 최종 표현 |
|---:|---|---|---|---|
| 1 | `aws_security_group.primary_bastion` | `bastion.tf:64` | VPC / Network | VPC/계층 경계 주석 |
| 2 | `aws_security_group.dr_bastion` | `bastion.tf:159` | VPC / Network | VPC/계층 경계 주석 |
| 3 | `aws_flow_log.primary_reject` | `observability.tf:255` | VPC / Network | 로그 연결 라벨: VPC REJECT Flow |
| 4 | `aws_security_group.primary_alb` | `securitygroups.tf:6` | VPC / Network | VPC/계층 경계 주석 |
| 5 | `aws_security_group.dr_alb` | `securitygroups.tf:27` | VPC / Network | VPC/계층 경계 주석 |
| 6 | `aws_vpc_security_group_ingress_rule.primary_alb_to_web_nodes` | `securitygroups.tf:48` | VPC / Network | VPC/계층 경계 주석 |
| 7 | `aws_vpc_security_group_ingress_rule.dr_alb_to_web_nodes` | `securitygroups.tf:59` | VPC / Network | VPC/계층 경계 주석 |
| 8 | `aws_security_group.primary_data` | `securitygroups.tf:71` | VPC / Network | VPC/계층 경계 주석 |
| 9 | `aws_security_group.dr_data` | `securitygroups.tf:97` | VPC / Network | VPC/계층 경계 주석 |
| 10 | `aws_security_group.primary_efs` | `storage-access.tf:39` | VPC / Network | VPC/계층 경계 주석 |
| 11 | `aws_security_group.dr_efs` | `storage-access.tf:81` | VPC / Network | VPC/계층 경계 주석 |
| 12 | `aws_route53_record.app` | `edge.tf:161` | Amazon Route 53 | 대표 DNS 아이콘 |
| 13 | `aws_route53_record.cloudfront_certificate_validation` | `foundation/edge.tf:20` | Amazon Route 53 | ACM validation 내부 DNS record |
| 14 | `aws_acm_certificate.cloudfront` | `foundation/edge.tf:9` | AWS Certificate Manager | 대표 TLS 아이콘 |
| 15 | `aws_acm_certificate_validation.cloudfront` | `foundation/edge.tf:37` | AWS Certificate Manager | ACM 내부 validation |
| 16 | `aws_cloudfront_distribution.this` | `edge.tf:119` | Amazon CloudFront | 대표 아이콘 |
| 17 | `aws_cloudwatch_log_delivery_destination.cloudfront_s3` | `foundation/observability.tf:128` | Amazon CloudFront | 로그 다이어그램에 Access Log 전달 위임 |
| 18 | `aws_cloudwatch_log_delivery_source.cloudfront_access` | `observability.tf:34` | Amazon CloudFront | 로그 다이어그램에 Access Log 전달 위임 |
| 19 | `aws_cloudwatch_log_delivery.cloudfront_access` | `observability.tf:42` | Amazon CloudFront | 로그 다이어그램에 Access Log 전달 위임 |
| 20 | `aws_wafv2_web_acl.edge` | `observability.tf:74` | AWS WAF | 대표 아이콘 |
| 21 | `aws_wafv2_web_acl_logging_configuration.edge` | `observability.tf:214` | AWS WAF | 로그 다이어그램에 WAF logging 위임 |
| 22 | `aws_lb.primary` | `edge.tf:2` | Application Load Balancer | 역할 노드: Primary/DR |
| 23 | `aws_lb_target_group.primary` | `edge.tf:20` | Application Load Balancer | ALB 내부 Listener/Target Group |
| 24 | `aws_lb_listener.primary` | `edge.tf:38` | Application Load Balancer | ALB 내부 Listener/Target Group |
| 25 | `aws_lb.dr` | `edge.tf:51` | Application Load Balancer | 역할 노드: Primary/DR |
| 26 | `aws_lb_target_group.dr` | `edge.tf:61` | Application Load Balancer | ALB 내부 Listener/Target Group |
| 27 | `aws_lb_listener.dr` | `edge.tf:82` | Application Load Balancer | ALB 내부 Listener/Target Group |
| 28 | `helm_release.primary_aws_load_balancer_controller` | `cluster-controllers.tf:36` | Amazon EKS | EKS 내부 chip: Load Balancer Controller |
| 29 | `helm_release.dr_aws_load_balancer_controller` | `cluster-controllers.tf:63` | Amazon EKS | EKS 내부 chip: Load Balancer Controller |
| 30 | `helm_release.primary_external_dns` | `cluster-controllers.tf:136` | Amazon EKS | EKS 내부 chip: ExternalDNS |
| 31 | `helm_release.dr_external_dns` | `cluster-controllers.tf:163` | Amazon EKS | EKS 내부 chip: ExternalDNS |
| 32 | `helm_release.primary_karpenter` | `eks.tf:169` | Amazon EKS | EKS 내부 chip: Karpenter |
| 33 | `helm_release.dr_karpenter` | `eks.tf:195` | Amazon EKS | EKS 내부 chip: Karpenter |
| 34 | `helm_release.primary_karpenter_node_config` | `eks.tf:221` | Amazon EKS | EKS 내부 chip: Karpenter |
| 35 | `helm_release.dr_karpenter_node_config` | `eks.tf:240` | Amazon EKS | EKS 내부 chip: Karpenter |
| 36 | `helm_release.primary_web_target_group_binding` | `target-group-binding.tf:1` | Amazon EKS | 연결 라벨: ALB → TGB → Service |
| 37 | `helm_release.dr_web_target_group_binding` | `target-group-binding.tf:23` | Amazon EKS | 연결 라벨: ALB → TGB → Service |
| 38 | `aws_ecr_repository.application` | `foundation/main.tf:82` | Amazon ECR | 대표 아이콘 |
| 39 | `aws_ecr_lifecycle_policy.application` | `foundation/main.tf:99` | Amazon ECR | ECR lifecycle 속성 |
| 40 | `aws_instance.primary_bastion` | `bastion.tf:91` | Bastion EC2 | 역할 노드: Primary/DR Bastion |
| 41 | `aws_instance.dr_bastion` | `bastion.tf:187` | Bastion EC2 | 역할 노드: Primary/DR Bastion |
| 42 | `aws_ssm_document.primary_cluster_addons` | `cluster-addons-ssm.tf:51` | AWS Systems Manager | SSM 내부 Document/Association |
| 43 | `aws_ssm_association.primary_cluster_addons` | `cluster-addons-ssm.tf:72` | AWS Systems Manager | SSM 내부 Document/Association |
| 44 | `aws_ssm_document.dr_cluster_addons` | `cluster-addons-ssm.tf:93` | AWS Systems Manager | SSM 내부 Document/Association |
| 45 | `aws_ssm_association.dr_cluster_addons` | `cluster-addons-ssm.tf:114` | AWS Systems Manager | SSM 내부 Document/Association |
| 46 | `aws_iam_role.primary_bastion` | `bastion.tf:33` | AWS IAM | IAM 관계 묶음 |
| 47 | `aws_iam_role_policy_attachment.primary_bastion_ssm` | `bastion.tf:39` | AWS IAM | IAM 관계 묶음 |
| 48 | `aws_iam_role_policy.primary_bastion_eks_describe` | `bastion.tf:45` | AWS IAM | IAM 관계 묶음 |
| 49 | `aws_iam_instance_profile.primary_bastion` | `bastion.tf:58` | AWS IAM | IAM 관계 묶음 |
| 50 | `aws_iam_role.dr_bastion` | `bastion.tf:124` | AWS IAM | IAM 관계 묶음 |
| 51 | `aws_iam_role_policy_attachment.dr_bastion_ssm` | `bastion.tf:131` | AWS IAM | IAM 관계 묶음 |
| 52 | `aws_iam_role_policy.dr_bastion_eks_describe` | `bastion.tf:138` | AWS IAM | IAM 관계 묶음 |
| 53 | `aws_iam_instance_profile.dr_bastion` | `bastion.tf:152` | AWS IAM | IAM 관계 묶음 |
| 54 | `aws_iam_role.guardduty_eventbridge` | `foundation/detection.tf:224` | AWS IAM | IAM 관계 묶음 |
| 55 | `aws_iam_role_policy.guardduty_eventbridge_publish` | `foundation/detection.tf:242` | AWS IAM | IAM 관계 묶음 |
| 56 | `aws_iam_openid_connect_provider.github_actions` | `foundation/main.tf:121` | AWS IAM | IAM 관계 묶음 |
| 57 | `aws_iam_role.github_actions_ecr` | `foundation/main.tf:157` | AWS IAM | IAM 관계 묶음 |
| 58 | `aws_iam_role_policy.github_actions_ecr` | `foundation/main.tf:190` | AWS IAM | IAM 관계 묶음 |
| 59 | `aws_iam_role.cloudtrail_logs` | `foundation/observability.tf:142` | AWS IAM | IAM 관계 묶음 |
| 60 | `aws_iam_role_policy.cloudtrail_logs` | `foundation/observability.tf:164` | AWS IAM | IAM 관계 묶음 |
| 61 | `aws_iam_role.primary_dvwa_log_forwarder` | `observability.tf:265` | AWS IAM | IAM 관계 묶음 |
| 62 | `aws_iam_role_policy.primary_dvwa_log_forwarder` | `observability.tf:272` | AWS IAM | IAM 관계 묶음 |
| 63 | `aws_iam_role.dr_dvwa_log_forwarder` | `observability.tf:301` | AWS IAM | IAM 관계 묶음 |
| 64 | `aws_iam_role_policy.dr_dvwa_log_forwarder` | `observability.tf:308` | AWS IAM | IAM 관계 묶음 |
| 65 | `aws_iam_role.primary_efs_csi` | `storage-access.tf:11` | AWS IAM | IAM 관계 묶음 |
| 66 | `aws_iam_role_policy_attachment.primary_efs_csi` | `storage-access.tf:18` | AWS IAM | IAM 관계 묶음 |
| 67 | `aws_iam_role.dr_efs_csi` | `storage-access.tf:25` | AWS IAM | IAM 관계 묶음 |
| 68 | `aws_iam_role_policy_attachment.dr_efs_csi` | `storage-access.tf:32` | AWS IAM | IAM 관계 묶음 |
| 69 | `aws_iam_role.primary_web_s3` | `storage-access.tf:123` | AWS IAM | IAM 관계 묶음 |
| 70 | `aws_iam_role_policy.primary_web_s3` | `storage-access.tf:130` | AWS IAM | IAM 관계 묶음 |
| 71 | `aws_iam_role.dr_web_s3` | `storage-access.tf:152` | AWS IAM | IAM 관계 묶음 |
| 72 | `aws_iam_role_policy.dr_web_s3` | `storage-access.tf:159` | AWS IAM | IAM 관계 묶음 |
| 73 | `aws_iam_role.s3_replication` | `storage-observability.tf:67` | AWS IAM | IAM 관계 묶음 |
| 74 | `aws_iam_role_policy.s3_replication` | `storage-observability.tf:77` | AWS IAM | IAM 관계 묶음 |
| 75 | `aws_eks_pod_identity_association.primary_dvwa_log_forwarder` | `observability.tf:292` | EKS Pod Identity | Pod Identity 관계 묶음 |
| 76 | `aws_eks_pod_identity_association.dr_dvwa_log_forwarder` | `observability.tf:328` | EKS Pod Identity | Pod Identity 관계 묶음 |
| 77 | `aws_eks_pod_identity_association.primary_web_s3` | `storage-access.tf:143` | EKS Pod Identity | Pod Identity 관계 묶음 |
| 78 | `aws_eks_pod_identity_association.dr_web_s3` | `storage-access.tf:172` | EKS Pod Identity | Pod Identity 관계 묶음 |
| 79 | `aws_db_instance.primary` | `data.tf:13` | Amazon RDS | 역할 노드: Primary/DR Replica |
| 80 | `aws_kms_key.dr_rds` | `data.tf:39` | Amazon RDS | RDS 속성: KMS encryption |
| 81 | `aws_kms_alias.dr_rds` | `data.tf:47` | Amazon RDS | RDS 속성: KMS encryption |
| 82 | `aws_db_instance.dr_replica` | `data.tf:54` | Amazon RDS | 역할 노드: Primary/DR Replica |
| 83 | `aws_elasticache_subnet_group.primary` | `data.tf:69` | Amazon ElastiCache / Valkey | 내부 subnet group |
| 84 | `aws_elasticache_replication_group.primary` | `data.tf:76` | Amazon ElastiCache / Valkey | 역할 노드: Primary/DR |
| 85 | `aws_elasticache_subnet_group.dr` | `data.tf:93` | Amazon ElastiCache / Valkey | 내부 subnet group |
| 86 | `aws_elasticache_replication_group.dr` | `data.tf:100` | Amazon ElastiCache / Valkey | 역할 노드: Primary/DR |
| 87 | `aws_efs_file_system.primary` | `storage-access.tf:63` | Amazon EFS | 역할 노드: Primary/DR |
| 88 | `aws_efs_mount_target.primary` | `storage-access.tf:71` | Amazon EFS | 내부 mount target |
| 89 | `aws_efs_file_system.dr` | `storage-access.tf:105` | Amazon EFS | 역할 노드: Primary/DR |
| 90 | `aws_efs_mount_target.dr` | `storage-access.tf:113` | Amazon EFS | 내부 mount target |
| 91 | `aws_s3_bucket.security_logs` | `foundation/observability.tf:8` | Amazon S3 | 역할 노드: App Primary/App DR/Security Logs |
| 92 | `aws_s3_bucket_versioning.security_logs` | `foundation/observability.tf:17` | Amazon S3 | S3 속성 |
| 93 | `aws_s3_bucket_server_side_encryption_configuration.security_logs` | `foundation/observability.tf:25` | Amazon S3 | S3 속성 |
| 94 | `aws_s3_bucket_public_access_block.security_logs` | `foundation/observability.tf:35` | Amazon S3 | S3 속성 |
| 95 | `aws_s3_bucket_lifecycle_configuration.security_logs` | `foundation/observability.tf:43` | Amazon S3 | S3 속성 |
| 96 | `aws_s3_bucket_policy.security_logs` | `foundation/observability.tf:182` | Amazon S3 | S3 속성 |
| 97 | `aws_s3_bucket.primary` | `storage-observability.tf:1` | Amazon S3 | 역할 노드: App Primary/App DR/Security Logs |
| 98 | `aws_s3_bucket.dr` | `storage-observability.tf:7` | Amazon S3 | 역할 노드: App Primary/App DR/Security Logs |
| 99 | `aws_s3_bucket_versioning.primary` | `storage-observability.tf:14` | Amazon S3 | S3 속성 |
| 100 | `aws_s3_bucket_versioning.dr` | `storage-observability.tf:20` | Amazon S3 | S3 속성 |
| 101 | `aws_s3_bucket_server_side_encryption_configuration.primary` | `storage-observability.tf:27` | Amazon S3 | S3 속성 |
| 102 | `aws_s3_bucket_server_side_encryption_configuration.dr` | `storage-observability.tf:37` | Amazon S3 | S3 속성 |
| 103 | `aws_s3_bucket_public_access_block.primary` | `storage-observability.tf:48` | Amazon S3 | S3 속성 |
| 104 | `aws_s3_bucket_public_access_block.dr` | `storage-observability.tf:57` | Amazon S3 | S3 속성 |
| 105 | `aws_s3_bucket_replication_configuration.primary_to_dr` | `storage-observability.tf:91` | Amazon S3 | 연결 라벨: Primary → DR replication |
| 106 | `aws_cloudwatch_log_metric_filter.dvwa_login_failures` | `foundation/detection.tf:53` | Amazon CloudWatch | CloudWatch 내부 Detection |
| 107 | `aws_cloudwatch_metric_alarm.dvwa_login_failures` | `foundation/detection.tf:74` | Amazon CloudWatch | CloudWatch 내부 Detection |
| 108 | `aws_cloudwatch_log_group.guardduty_findings` | `foundation/detection.tf:128` | Amazon CloudWatch | CloudWatch 내부 Log Group |
| 109 | `aws_cloudwatch_log_resource_policy.guardduty_eventbridge` | `foundation/detection.tf:155` | Amazon CloudWatch | CloudWatch 내부 delivery policy |
| 110 | `aws_cloudwatch_log_group.cloudtrail` | `foundation/observability.tf:79` | Amazon CloudWatch | CloudWatch 내부 Log Group |
| 111 | `aws_cloudwatch_log_group.eks_primary` | `foundation/observability.tf:88` | Amazon CloudWatch | CloudWatch 내부 Log Group |
| 112 | `aws_cloudwatch_log_group.dvwa_primary` | `foundation/observability.tf:97` | Amazon CloudWatch | CloudWatch 내부 Log Group |
| 113 | `aws_cloudwatch_log_group.dvwa_dr` | `foundation/observability.tf:106` | Amazon CloudWatch | CloudWatch 내부 Log Group |
| 114 | `aws_cloudwatch_log_group.waf_edge` | `foundation/observability.tf:118` | Amazon CloudWatch | CloudWatch 내부 Log Group |
| 115 | `aws_cloudtrail.security` | `foundation/observability.tf:266` | AWS CloudTrail | 대표 아이콘 |
| 116 | `aws_guardduty_detector.primary` | `foundation/detection.tf:98` | Amazon GuardDuty | 대표 아이콘 |
| 117 | `aws_guardduty_detector_feature.disabled_optional` | `foundation/detection.tf:107` | Amazon GuardDuty | GuardDuty 내부 feature |
| 118 | `aws_cloudwatch_event_rule.guardduty_findings` | `foundation/detection.tf:137` | Amazon EventBridge | 대표 routing 아이콘 |
| 119 | `aws_cloudwatch_event_target.guardduty_log` | `foundation/detection.tf:181` | Amazon EventBridge | EventBridge 내부 target |
| 120 | `aws_cloudwatch_event_target.guardduty_alert` | `foundation/detection.tf:252` | Amazon EventBridge | EventBridge 내부 target |
| 121 | `aws_sns_topic.security_alerts` | `foundation/detection.tf:21` | Amazon SNS | 대표 알림 아이콘 |
| 122 | `aws_sns_topic_subscription.security_alert_email` | `foundation/detection.tf:29` | Amazon SNS | SNS 내부 subscription |
| 123 | `random_password.db_master` | `data.tf:1` | Terraform Local Material | 생략: Terraform 내부 값 |
| 124 | `random_password.dvwa_app` | `data.tf:8` | Terraform Local Material | 생략: Terraform 내부 값 |

## 검증

- 프로젝트 소유 `resource`: **124**
- 귀속 완료: **124**
- 미귀속: **0**
- 중복 source key: **0**
- 보이는 서비스 가족: **21**
- 역할별 노드: **28**
- VPC 구조 경계: **2**
- 숨기는 Terraform 로컬 리소스: **2**
- Module 문맥: **10개 전부 귀속**

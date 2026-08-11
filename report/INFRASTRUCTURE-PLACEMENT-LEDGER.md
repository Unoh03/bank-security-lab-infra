# Infrastructure Placement Ledger

> 목적: Draw.io 제작 전에 Source의 모든 배치 가능한 요소와 부속 설정을 추적하는 작업 장부.
> 이 문서는 멘토에게 직접 보여 줄 발표 자료가 아니다. Source/state 등재는 Runtime 활성 증명이 아니다.

## Coverage

- 기준일: 2026-08-10
- 프로젝트 소유 Terraform: 20/20 파일 정독
- Top-level block 대조: 299개
- 직접 resource: 124개
- module: 10개
- data: 16개
- Current state address snapshot: Daily 163개, Foundation 48개
- Module-expanded state: VPC 24, EKS 53, Karpenter 28, LBC Pod Identity 10, ExternalDNS Pod Identity 10 addresses
- 제외: .terraform의 사용하지 않는 optional module 코드, tfstate attribute 값, tfvars/credentials, Runtime API 활성 확인

## Representation Rules

- 독립 AWS 서비스와 실행 구성요소는 아이콘 또는 그룹 카드로 배치한다.
- Region, VPC, AZ, Subnet, Foundation/Daily lifecycle은 경계로 배치한다.
- IAM policy/attachment, bucket 설정, SG rule, route association은 부모 요소의 라벨 또는 관계선으로 흡수한다.
- 기본 비활성 자원은 본편 경로에 섞지 않고 점선 Optional/DR 영역에 둔다.
- 모든 직접 resource/module/data는 아래 전수 대조 부록에서 Logical ID로 역추적한다.

## Logical Placement Board

| ID | Layer | Source status | Diagram form | Logical placement | Element / Source mapping |
|---|---|---|---|---|---|
| BND-01 | 경계 | 외부 | 경계 | AWS Cloud 밖 | 사용자 · 개발자 · GitHub · 운영자 PC |
| BND-02 | 경계 | 지속 | 경계 | AWS Cloud 안 / Daily와 분리 | Persistent Foundation · 별도 state · prevent_destroy |
| BND-03 | 경계 | 일일 | 경계 | AWS Cloud 안 / Foundation과 분리 | Daily Runtime · daily-up/down 대상 |
| BND-04 | 경계 | 기본 활성 | 경계 | Global / us-east-1 및 CloudFront scope | aws.global · CloudFront · WAF · ACM |
| BND-05 | 경계 | 기본 활성 | 경계 | ap-northeast-2 | Primary Region |
| BND-06 | 경계 | 기본 활성 | 경계 | Primary Region 내부 | Primary VPC · AZ 2a/2c · Public/Private/DB Subnet |
| BND-07 | 경계 | 기본 비활성 | 점선 경계 | ap-northeast-1 | DR Region · runtime_profile dr-test/full |
| FND-01 | Foundation | domain 조건 / state 등재 | 외부 선행 자원 | AWS Cloud global | data.aws_route53_zone.existing · Terraform이 Hosted Zone을 생성하지 않음 |
| FND-02 | Foundation | domain 조건 / state 등재 | 독립 아이콘+부속 라벨 | us-east-1 | ACM Certificate · DNS Validation Record · Certificate Validation |
| FND-03 | Foundation | 기본 활성 / state 등재 | 그룹 카드 | AWS account global | GitHub OIDC Provider · ECR Push IAM Role/Policy |
| FND-04 | Foundation | 기본 활성 / state 등재 | 독립 아이콘 | ap-northeast-2 regional | ECR Repository · Immutable · Scan on Push · Lifecycle Policy |
| FND-05 | Foundation | 기본 활성 / state 등재 | 독립 아이콘+부속 라벨 | ap-northeast-2 | Security Log S3 · Versioning · AES256 · Public Block · Lifecycle · Bucket Policy |
| FND-06 | Foundation | 기본 활성 / state 등재 | 그룹 카드 | Seoul/Tokyo/us-east-1 | CloudWatch Log Groups: CloudTrail · EKS · DVWA · WAF · GuardDuty |
| FND-07 | Foundation | 기본 활성 / state 등재 | 독립 아이콘+IAM 부속 | ap-northeast-2 / multi-region trail | CloudTrail · CloudWatch delivery role/policy · Security S3 archive |
| FND-08 | Foundation | 기본 활성 / state 등재 | 탐지 체인 | ap-northeast-2 | DVWA login failure Metric Filter → CloudWatch Alarm |
| FND-09 | Foundation | Topic 활성 / Email 기본 비활성 | 독립 아이콘+조건부 endpoint | ap-northeast-2 | SNS Security Alert Topic · optional email subscription |
| FND-10 | Foundation | 기본 활성 / state 등재 | 독립 아이콘+상태 주석 | ap-northeast-2 | GuardDuty foundational detector · optional protection features disabled |
| FND-11 | Foundation | 기본 활성 / state 등재 | 탐지 체인 | ap-northeast-2 | GuardDuty → EventBridge → CloudWatch Logs + SNS · IAM delivery role |
| FND-12 | Foundation | 기본 활성 | 계약 카드 | Foundation ↔ Daily 경계 | terraform_remote_state output contract v2 |
| GLB-01 | Daily Global | domain 조건 / state 등재 | 독립 아이콘 | Route 53 global | Application Alias Record → CloudFront |
| GLB-02 | Daily Global | 기본 활성 / state 등재 | 독립 아이콘 | CloudFront global | CloudFront Distribution · Primary ALB origin · HTTPS redirect |
| GLB-03 | Daily Global | 기본 활성 / state 등재 | 독립 아이콘+규칙 주석 | CloudFront scope / us-east-1 | WAF Web ACL · Common+SQLi COUNT · optional login rate rule · filtered logging |
| GLB-04 | Daily Global | 기본 활성 / state 등재 | 관계선 | CloudFront → Foundation S3 | CloudWatch Log Delivery Source/Delivery → persistent destination |
| NET-01 | Primary Network | 기본 활성 / module state 등재 | VPC 경계 | ap-northeast-2 | module.primary_vpc · 10.0.0.0/16 |
| NET-02 | Primary Network | 기본 활성 / module state 등재 | 독립 아이콘 | VPC edge | Internet Gateway |
| NET-03 | Primary Network | 기본 활성 / module state 등재 | Subnet 경계 2개 | AZ 2a/2c | Public Subnets 10.0.0.0/24 · 10.0.1.0/24 |
| NET-04 | Primary Network | 기본 활성 / module state 등재 | Subnet 경계 2개 | AZ 2a/2c | Private Subnets 10.0.10.0/24 · 10.0.11.0/24 |
| NET-05 | Primary Network | 기본 활성 / module state 등재 | Subnet 경계 2개+그룹 | AZ 2a/2c | Database Subnets 10.0.20.0/24 · 10.0.21.0/24 · DB Subnet Group |
| NET-06 | Primary Network | 기본 활성 / 1개 | 독립 아이콘 | Public Subnet 0 | EIP + single NAT Gateway · one_nat_gateway_per_az는 기본 false |
| NET-07 | Primary Network | 기본 활성 / module state 등재 | 관계선+작은 라벨 | VPC Subnets | Public/Private Route Tables · Routes · 6 Associations |
| NET-08 | Primary Network | 기본 활성 | 보안 경계/관계선 | VPC와 Workload 경계 | ALB · Data · Bastion · EKS cluster/node Security Groups와 rules |
| RUN-01 | Primary Runtime | 기본 활성 / state 등재 | 독립 아이콘+부속 라벨 | Public Subnets 2개 | Internet-facing ALB · HTTP Listener · CloudFront prefix-list ingress |
| RUN-02 | Primary Runtime | 기본 활성 / state 등재 | 관계 카드 | ALB ↔ Private Pod IP | Target Group target_type=ip · health /login.php · node SG ingress |
| RUN-03 | Primary Runtime | 기본 활성 / module state 등재 | 독립 아이콘 | Private Subnets 2개 | EKS Control Plane · private endpoint only · api/audit/authenticator logs |
| RUN-04 | Primary Runtime | 기본 활성 / module state 등재 | EKS 부속 라벨 | EKS 관리 경계 | Cluster IAM/OIDC/KMS · access entries · cluster/node SG rules |
| RUN-05 | Primary Runtime | 기본 활성 / module state 등재 | 노드 그룹 카드 | Private Subnets | Managed system Node Group · Launch Template · IAM Role · minimal desired=1 |
| RUN-06 | Primary Runtime | 기본 활성 / module state 등재 | EKS 내부 카드 | EKS | CoreDNS · kube-proxy · VPC CNI · EKS Pod Identity Agent |
| RUN-07 | Primary Runtime | 기본 활성 / module state 등재 | 그룹 카드 | EKS + regional services | Karpenter IAM · Pod Identity · Access Entry · SQS · EventBridge rules/targets |
| RUN-08 | Primary Runtime | 기본 활성 / module state 등재 | IAM 연결 | EKS kube-system | AWS Load Balancer Controller Pod Identity Role/Policy/Association |
| RUN-09 | Primary Runtime | domain 조건 / module state 등재 | IAM 연결 | EKS external-dns | ExternalDNS Pod Identity Role/Policy/Association |
| RUN-10 | Primary Runtime | 기본 활성 / state 등재 | 독립 아이콘+IAM 부속 | Public Subnet 0 | AL2023 Bastion · public IP · Key Pair · SSM IAM · EKS Describe/Admin access |
| RUN-11 | Primary Runtime | 기본 활성 / state 등재 | 관리 관계선 | SSM → Bastion → Private EKS API | SSM Document + Association · 기본 add-on 설치 경로 |
| RUN-12 | Primary Runtime | 기본 비활성 | 점선 컴포넌트 | EKS | Local Helm alternative: Karpenter/LBC/ExternalDNS/TGB releases |
| DATA-01 | Primary Data | 기본 활성 / state 등재 | 독립 아이콘+보안 라벨 | DB Subnets | RDS MariaDB · encrypted · private · minimal Single-AZ · generated passwords |
| DATA-02 | Primary Data | 기본 활성 / state 등재 | 독립 아이콘+부속 라벨 | Regional / VPC 밖 | Daily Application S3 · Versioning · AES256 · Public Block · force_destroy |
| OBS-01 | Daily Observability | 기본 활성 / state 등재 | 로그 관계선 | Primary VPC → Foundation S3 | VPC Flow Log · REJECT only |
| OBS-02 | Daily Observability | 기본 활성 / state 등재 | IAM 연결+로그 관계선 | EKS → Foundation CloudWatch Logs | DVWA Fluent Bit Pod Identity Role/Policy/Association |
| OPT-01 | Optional | 기본 비활성 | 점선 관계 | BANK Pod → Application S3 | Web ServiceAccount S3 Pod Identity |
| OPT-02 | Optional | 기본 비활성 | 점선 독립 아이콘 | Private Subnets 2개 | EFS · Mount Targets · SG · EFS CSI Pod Identity/IAM |
| OPT-03 | Optional | 기본 비활성 | 점선 독립 아이콘 | Database Subnets | Valkey replication group · subnet group · Data SG |
| DR-01 | Conditional DR | dr-test/full | 점선 VPC/AZ/Subnet 경계 | ap-northeast-1 | DR VPC · IGW · NAT · Public/Private/DB Subnets |
| DR-02 | Conditional DR | dr-test/full | 점선 EKS 그룹 | DR Private Subnets | DR EKS · system node group · Karpenter · controller identities |
| DR-03 | Conditional DR | dr-test/full | 점선 edge 그룹 | DR Public Subnets | DR ALB · Listener · Target Group · SG/TGB |
| DR-04 | Conditional DR | dr-test/full | 점선 데이터 그룹 | DR DB Subnets | Cross-region RDS Replica · dedicated KMS key/alias |
| DR-05 | Conditional DR | dr-test/full | 점선 데이터 그룹 | Tokyo regional | DR Application S3 · Versioning/Encryption/Public Block · Primary→DR replication |
| DR-06 | Conditional DR | dr-test/full | 점선 관리 그룹 | DR Public Subnet 0 | DR Bastion · IAM · SSM Document/Association |
| DR-07 | Conditional DR | DR + 추가 Gate | 점선 부속 그룹 | DR EKS/Data | DR Argo/ExternalDNS/Helm · DVWA logs · EFS · Valkey · Web S3 identity |
| NTF-01 | Source 외부 | 후속 대조 | 외부 카드 | AWS Cloud 밖 | GitHub Repository · Actions workflow · GitOps commit |
| NTF-02 | Source 외부 | 후속 대조 | EKS 내부 카드 | Bastion/SSM install template | Argo CD · LBC · ExternalDNS · Karpenter · Fluent Bit actual install |
| NTF-03 | Source 외부 | 후속 대조 | EKS workload 카드 | dvwa namespace | Deployment · Pod · Service · TargetGroupBinding · ServiceAccount |
| NTF-04 | Source 외부 | 후속 대조 | 로컬 카드 | AWS Cloud 밖 | Start-WafLiveViewer.ps1 · Local Docker Grafana · Query/Evidence |
| NTF-05 | Source 외부 | 후속 대조 | Lifecycle rail | 운영자 PC ↔ Foundation/Daily | setup-foundation · daily-up · daily-down · evidence collection |

## Feature Gates

| Gate | Default/Profile | Diagram consequence |
|---|---|---|
| runtime_profile=minimal | 기본 | DR off · Primary nodes 1/max2 · RDS Single-AZ |
| runtime_profile=dr-test | 조건부 | DR on · Primary nodes 1/max2 · RDS Single-AZ |
| runtime_profile=full | 조건부 | DR on · Primary nodes 2/max4 · RDS Multi-AZ |
| single_nat_gateway | true | Primary/DR 각각 NAT 1개 |
| enable_argocd | true | SSM add-on script에서 Primary Argo CD 설치 |
| enable_dr_argocd | false | DR Argo CD 기본 미설치 |
| manage_addons_via_local_helm | false | Terraform helm_release 대신 SSM Bastion 경로가 기본 |
| enable_edge_access_logging | true | CloudFront/Primary ALB access logs |
| enable_waf_observation | true | CloudFront WAF COUNT 관측 |
| waf_login_rate_rule_mode | disabled | WEB-01 rate rule 기본 없음 |
| enable_vpc_reject_flow_logs | true | Primary VPC REJECT only |
| enable_dvwa_log_collection | true | Fluent Bit용 IAM/Pod Identity |
| enable_web_s3_pod_identity | false | BANK Pod의 Application S3 권한 기본 없음 |
| enable_valkey | false | Primary/DR Valkey 미생성 |
| enable_efs | false | Primary/DR EFS와 CSI IAM 미생성 |
| enable_https_redirect | true | CloudFront viewer HTTP→HTTPS |
| enable_dr_external_dns | false | DR Hosted Zone 변경 금지 |
| Foundation enable_project_s3_data_events | false | CloudTrail management events만 |
| Foundation enable_security_alert_email_subscription | false | SNS Topic만, email endpoint 없음 |

## Current State Snapshot Interpretation

- Daily state에는 Primary VPC/EKS/Karpenter/LBC/ExternalDNS, ALB, CloudFront/WAF, Bastion/SSM, RDS, Application S3, DVWA log forwarding 관련 주소가 등재되어 있다.
- Daily state에는 DR, EFS, Valkey, Web S3 Pod Identity, Terraform helm_release 주소가 등재되어 있지 않다.
- Foundation state에는 ECR, GitHub OIDC/IAM, ACM/validation, Security S3, CloudWatch Log Groups, CloudTrail, GuardDuty, EventBridge, SNS/Alarm 주소가 등재되어 있다.
- 위 내용은 state 주소의 존재만 말한다. 현재 AWS API에서 실행 중인지, 로그가 지금 유입되는지는 별도 Runtime Evidence가 필요하다.

## Module-expanded Active Placement

| Logical ID | Module | State addresses | Managed resource addresses | Placement effect |
|---|---|---:|---:|---|
| NET-01~07 | module.primary_vpc | 24 | 24 | VPC, IGW, NAT/EIP, Subnets, Route Tables/Routes/Associations, DB Subnet Group |
| RUN-03~06 | module.primary_eks | 53 | 39 | EKS, IAM/OIDC/KMS, SG/rules, access entries, add-ons, node group/launch template |
| RUN-07 | module.primary_karpenter | 28 | 20 | IAM, Pod Identity, EKS Access, SQS, EventBridge interruption/event routing |
| RUN-08 | module.primary_aws_lb_controller_pod_identity | 10 | 4 | LBC IAM Role/Policy/Attachment/Association |
| RUN-09 | module.primary_external_dns_pod_identity | 10 | 4 | ExternalDNS IAM Role/Policy/Attachment/Association |

## Direct Resource Coverage

| Logical ID | Terraform address | Condition | State address | Representation | Source |
|---|---|---|---|---|---|
| RUN-10 | aws_iam_role.primary_bastion | always | yes | 아이콘/서비스 | bastion.tf:33 |
| RUN-10 | aws_iam_role_policy_attachment.primary_bastion_ssm | always | yes | 부속 설정/관계 | bastion.tf:39 |
| RUN-10 | aws_iam_role_policy.primary_bastion_eks_describe | always | yes | 부속 설정/관계 | bastion.tf:45 |
| RUN-10 | aws_iam_instance_profile.primary_bastion | always | yes | 아이콘/서비스 | bastion.tf:58 |
| RUN-10 | aws_security_group.primary_bastion | always | yes | 보안 경계/관계 | bastion.tf:64 |
| RUN-10 | aws_instance.primary_bastion | always | yes | 아이콘/서비스 | bastion.tf:91 |
| DR-06 | aws_iam_role.dr_bastion | count=local.enable_dr_runtime ? 1 : 0 | no | 아이콘/서비스 | bastion.tf:124 |
| DR-06 | aws_iam_role_policy_attachment.dr_bastion_ssm | count=local.enable_dr_runtime ? 1 : 0 | no | 부속 설정/관계 | bastion.tf:131 |
| DR-06 | aws_iam_role_policy.dr_bastion_eks_describe | count=local.enable_dr_runtime ? 1 : 0 | no | 부속 설정/관계 | bastion.tf:138 |
| DR-06 | aws_iam_instance_profile.dr_bastion | count=local.enable_dr_runtime ? 1 : 0 | no | 아이콘/서비스 | bastion.tf:152 |
| DR-06 | aws_security_group.dr_bastion | count=local.enable_dr_runtime ? 1 : 0 | no | 보안 경계/관계 | bastion.tf:159 |
| DR-06 | aws_instance.dr_bastion | count=local.enable_dr_runtime ? 1 : 0 | no | 아이콘/서비스 | bastion.tf:187 |
| RUN-11 | aws_ssm_document.primary_cluster_addons | always | yes | 아이콘/서비스 | cluster-addons-ssm.tf:51 |
| RUN-11 | aws_ssm_association.primary_cluster_addons | always | yes | 부속 설정/관계 | cluster-addons-ssm.tf:72 |
| DR-06 | aws_ssm_document.dr_cluster_addons | count=local.enable_dr_runtime ? 1 : 0 | no | 아이콘/서비스 | cluster-addons-ssm.tf:93 |
| DR-06 | aws_ssm_association.dr_cluster_addons | count=local.enable_dr_runtime ? 1 : 0 | no | 부속 설정/관계 | cluster-addons-ssm.tf:114 |
| RUN-12 | helm_release.primary_aws_load_balancer_controller | count=var.manage_addons_via_local_helm ? 1 : 0 | no | 조건부 EKS 컴포넌트 | cluster-controllers.tf:36 |
| DR-07 | helm_release.dr_aws_load_balancer_controller | count=local.enable_dr_runtime && var.manage_addons_via_local_helm ? 1 : 0 | no | 조건부 EKS 컴포넌트 | cluster-controllers.tf:63 |
| RUN-12 | helm_release.primary_external_dns | count=local.domain_name != "" && var.manage_addons_via_local_helm ? 1 : 0 | no | 조건부 EKS 컴포넌트 | cluster-controllers.tf:136 |
| DR-07 | helm_release.dr_external_dns | count=local.enable_dr_runtime && var.enable_dr_external_dns && local.domain_name != "" && var.manage | no | 조건부 EKS 컴포넌트 | cluster-controllers.tf:163 |
| DATA-01 | random_password.db_master | always | yes | 비시각 비밀 생성 | data.tf:1 |
| DATA-01 | random_password.dvwa_app | always | yes | 비시각 비밀 생성 | data.tf:8 |
| DATA-01 | aws_db_instance.primary | always | yes | 아이콘/서비스 | data.tf:13 |
| DR-04 | aws_kms_key.dr_rds | count=local.enable_dr_runtime ? 1 : 0 | no | 아이콘/서비스 | data.tf:39 |
| DR-04 | aws_kms_alias.dr_rds | count=local.enable_dr_runtime ? 1 : 0 | no | 부속 설정/관계 | data.tf:47 |
| DR-04 | aws_db_instance.dr_replica | count=local.enable_dr_runtime ? 1 : 0 | no | 아이콘/서비스 | data.tf:54 |
| OPT-03 | aws_elasticache_subnet_group.primary | count=var.enable_valkey ? 1 : 0 | no | 아이콘/서비스 | data.tf:69 |
| OPT-03 | aws_elasticache_replication_group.primary | count=var.enable_valkey ? 1 : 0 | no | 아이콘/서비스 | data.tf:76 |
| DR-07 | aws_elasticache_subnet_group.dr | count=local.enable_dr_runtime && var.enable_valkey ? 1 : 0 | no | 아이콘/서비스 | data.tf:93 |
| DR-07 | aws_elasticache_replication_group.dr | count=local.enable_dr_runtime && var.enable_valkey ? 1 : 0 | no | 아이콘/서비스 | data.tf:100 |
| RUN-01 | aws_lb.primary | always | yes | 아이콘/서비스 | edge.tf:2 |
| RUN-02 | aws_lb_target_group.primary | always | yes | 아이콘/서비스 | edge.tf:20 |
| RUN-01 | aws_lb_listener.primary | always | yes | 아이콘/서비스 | edge.tf:38 |
| DR-03 | aws_lb.dr | count=local.enable_dr_runtime ? 1 : 0 | no | 아이콘/서비스 | edge.tf:51 |
| DR-03 | aws_lb_target_group.dr | count=local.enable_dr_runtime ? 1 : 0 | no | 아이콘/서비스 | edge.tf:61 |
| DR-03 | aws_lb_listener.dr | count=local.enable_dr_runtime ? 1 : 0 | no | 아이콘/서비스 | edge.tf:82 |
| GLB-02 | aws_cloudfront_distribution.this | always | yes | 아이콘/서비스 | edge.tf:119 |
| GLB-01 | aws_route53_record.app | count=local.domain_name == "" ? 0 : 1 | yes | 아이콘/서비스 | edge.tf:161 |
| RUN-12 | helm_release.primary_karpenter | count=var.manage_addons_via_local_helm ? 1 : 0 | no | 조건부 EKS 컴포넌트 | eks.tf:169 |
| DR-02 | helm_release.dr_karpenter | count=local.enable_dr_runtime && var.manage_addons_via_local_helm ? 1 : 0 | no | 조건부 EKS 컴포넌트 | eks.tf:195 |
| RUN-12 | helm_release.primary_karpenter_node_config | count=var.manage_addons_via_local_helm ? 1 : 0 | no | 조건부 EKS 컴포넌트 | eks.tf:221 |
| DR-02 | helm_release.dr_karpenter_node_config | count=local.enable_dr_runtime && var.manage_addons_via_local_helm ? 1 : 0 | no | 조건부 EKS 컴포넌트 | eks.tf:240 |
| FND-09 | aws_sns_topic.security_alerts | always | yes | 아이콘/서비스 | foundation/detection.tf:21 |
| FND-09 | aws_sns_topic_subscription.security_alert_email | count=var.enable_security_alert_email_subscription ? 1 : 0 | no | 아이콘/서비스 | foundation/detection.tf:29 |
| FND-08 | aws_cloudwatch_log_metric_filter.dvwa_login_failures | always | yes | 아이콘/서비스 | foundation/detection.tf:53 |
| FND-08 | aws_cloudwatch_metric_alarm.dvwa_login_failures | always | yes | 아이콘/서비스 | foundation/detection.tf:74 |
| FND-10 | aws_guardduty_detector.primary | always | yes | 아이콘/서비스 | foundation/detection.tf:98 |
| FND-10 | aws_guardduty_detector_feature.disabled_optional | for_each=local.guardduty_disabled_features | yes | 아이콘/서비스 | foundation/detection.tf:107 |
| FND-06 | aws_cloudwatch_log_group.guardduty_findings | always | yes | 아이콘/서비스 | foundation/detection.tf:128 |
| FND-11 | aws_cloudwatch_event_rule.guardduty_findings | always | yes | 부속 설정/관계 | foundation/detection.tf:137 |
| FND-11 | aws_cloudwatch_log_resource_policy.guardduty_eventbridge | always | yes | 부속 설정/관계 | foundation/detection.tf:155 |
| FND-11 | aws_cloudwatch_event_target.guardduty_log | always | yes | 아이콘/서비스 | foundation/detection.tf:181 |
| FND-11 | aws_iam_role.guardduty_eventbridge | always | yes | 아이콘/서비스 | foundation/detection.tf:224 |
| FND-11 | aws_iam_role_policy.guardduty_eventbridge_publish | always | yes | 부속 설정/관계 | foundation/detection.tf:242 |
| FND-11 | aws_cloudwatch_event_target.guardduty_alert | always | yes | 아이콘/서비스 | foundation/detection.tf:252 |
| FND-02 | aws_acm_certificate.cloudfront | count=var.domain_name == "" ? 0 : 1 | yes | 아이콘/서비스 | foundation/edge.tf:9 |
| FND-02 | aws_route53_record.cloudfront_certificate_validation | for_each=var.domain_name == "" ? {} : { | yes | 아이콘/서비스 | foundation/edge.tf:20 |
| FND-02 | aws_acm_certificate_validation.cloudfront | count=var.domain_name == "" ? 0 : 1 | yes | 부속 설정/관계 | foundation/edge.tf:37 |
| FND-04 | aws_ecr_repository.application | always | yes | 아이콘/서비스 | foundation/main.tf:82 |
| FND-04 | aws_ecr_lifecycle_policy.application | always | yes | 부속 설정/관계 | foundation/main.tf:99 |
| FND-03 | aws_iam_openid_connect_provider.github_actions | count=var.create_github_oidc_provider ? 1 : 0 | yes | 아이콘/서비스 | foundation/main.tf:121 |
| FND-04 | aws_iam_role.github_actions_ecr | always | yes | 아이콘/서비스 | foundation/main.tf:157 |
| FND-04 | aws_iam_role_policy.github_actions_ecr | always | yes | 부속 설정/관계 | foundation/main.tf:190 |
| FND-05 | aws_s3_bucket.security_logs | always | yes | 아이콘/서비스 | foundation/observability.tf:8 |
| FND-05 | aws_s3_bucket_versioning.security_logs | always | yes | 부속 설정/관계 | foundation/observability.tf:17 |
| FND-05 | aws_s3_bucket_server_side_encryption_configuration.security_logs | always | yes | 부속 설정/관계 | foundation/observability.tf:25 |
| FND-05 | aws_s3_bucket_public_access_block.security_logs | always | yes | 부속 설정/관계 | foundation/observability.tf:35 |
| FND-05 | aws_s3_bucket_lifecycle_configuration.security_logs | always | yes | 부속 설정/관계 | foundation/observability.tf:43 |
| FND-06 | aws_cloudwatch_log_group.cloudtrail | always | yes | 아이콘/서비스 | foundation/observability.tf:79 |
| FND-06 | aws_cloudwatch_log_group.eks_primary | always | yes | 아이콘/서비스 | foundation/observability.tf:88 |
| FND-06 | aws_cloudwatch_log_group.dvwa_primary | always | yes | 아이콘/서비스 | foundation/observability.tf:97 |
| FND-06 | aws_cloudwatch_log_group.dvwa_dr | always | yes | 아이콘/서비스 | foundation/observability.tf:106 |
| FND-06 | aws_cloudwatch_log_group.waf_edge | always | yes | 아이콘/서비스 | foundation/observability.tf:118 |
| FND-05 | aws_cloudwatch_log_delivery_destination.cloudfront_s3 | always | yes | 아이콘/서비스 | foundation/observability.tf:128 |
| FND-07 | aws_iam_role.cloudtrail_logs | always | yes | 아이콘/서비스 | foundation/observability.tf:142 |
| FND-07 | aws_iam_role_policy.cloudtrail_logs | always | yes | 부속 설정/관계 | foundation/observability.tf:164 |
| FND-05 | aws_s3_bucket_policy.security_logs | always | yes | 부속 설정/관계 | foundation/observability.tf:182 |
| FND-07 | aws_cloudtrail.security | always | yes | 아이콘/서비스 | foundation/observability.tf:266 |
| GLB-04 | aws_cloudwatch_log_delivery_source.cloudfront_access | count=var.enable_edge_access_logging ? 1 : 0 | yes | 아이콘/서비스 | observability.tf:34 |
| GLB-04 | aws_cloudwatch_log_delivery.cloudfront_access | count=var.enable_edge_access_logging ? 1 : 0 | yes | 아이콘/서비스 | observability.tf:42 |
| GLB-03 | aws_wafv2_web_acl.edge | count=var.enable_waf_observation ? 1 : 0 | yes | 아이콘/서비스 | observability.tf:74 |
| GLB-03 | aws_wafv2_web_acl_logging_configuration.edge | count=var.enable_waf_observation ? 1 : 0 | yes | 아이콘/서비스 | observability.tf:214 |
| OBS-01 | aws_flow_log.primary_reject | count=var.enable_vpc_reject_flow_logs ? 1 : 0 | yes | 아이콘/서비스 | observability.tf:255 |
| OBS-02 | aws_iam_role.primary_dvwa_log_forwarder | count=var.enable_dvwa_log_collection ? 1 : 0 | yes | 아이콘/서비스 | observability.tf:265 |
| OBS-02 | aws_iam_role_policy.primary_dvwa_log_forwarder | count=var.enable_dvwa_log_collection ? 1 : 0 | yes | 부속 설정/관계 | observability.tf:272 |
| OBS-02 | aws_eks_pod_identity_association.primary_dvwa_log_forwarder | count=var.enable_dvwa_log_collection ? 1 : 0 | yes | 부속 설정/관계 | observability.tf:292 |
| DR-07 | aws_iam_role.dr_dvwa_log_forwarder | count=local.enable_dr_runtime && var.enable_dvwa_log_collection ? 1 : 0 | no | 아이콘/서비스 | observability.tf:301 |
| DR-07 | aws_iam_role_policy.dr_dvwa_log_forwarder | count=local.enable_dr_runtime && var.enable_dvwa_log_collection ? 1 : 0 | no | 부속 설정/관계 | observability.tf:308 |
| DR-07 | aws_eks_pod_identity_association.dr_dvwa_log_forwarder | count=local.enable_dr_runtime && var.enable_dvwa_log_collection ? 1 : 0 | no | 부속 설정/관계 | observability.tf:328 |
| RUN-01 | aws_security_group.primary_alb | always | yes | 보안 경계/관계 | securitygroups.tf:6 |
| DR-03 | aws_security_group.dr_alb | count=local.enable_dr_runtime ? 1 : 0 | no | 보안 경계/관계 | securitygroups.tf:27 |
| RUN-02 | aws_vpc_security_group_ingress_rule.primary_alb_to_web_nodes | always | yes | 부속 설정/관계 | securitygroups.tf:48 |
| DR-03 | aws_vpc_security_group_ingress_rule.dr_alb_to_web_nodes | count=local.enable_dr_runtime ? 1 : 0 | no | 부속 설정/관계 | securitygroups.tf:59 |
| NET-08 | aws_security_group.primary_data | always | yes | 보안 경계/관계 | securitygroups.tf:71 |
| DR-04 | aws_security_group.dr_data | count=local.enable_dr_runtime ? 1 : 0 | no | 보안 경계/관계 | securitygroups.tf:97 |
| OPT-02 | aws_iam_role.primary_efs_csi | count=var.enable_efs ? 1 : 0 | no | 아이콘/서비스 | storage-access.tf:11 |
| OPT-02 | aws_iam_role_policy_attachment.primary_efs_csi | count=var.enable_efs ? 1 : 0 | no | 부속 설정/관계 | storage-access.tf:18 |
| DR-07 | aws_iam_role.dr_efs_csi | count=local.enable_dr_runtime && var.enable_efs ? 1 : 0 | no | 아이콘/서비스 | storage-access.tf:25 |
| DR-07 | aws_iam_role_policy_attachment.dr_efs_csi | count=local.enable_dr_runtime && var.enable_efs ? 1 : 0 | no | 부속 설정/관계 | storage-access.tf:32 |
| OPT-02 | aws_security_group.primary_efs | count=var.enable_efs ? 1 : 0 | no | 보안 경계/관계 | storage-access.tf:39 |
| OPT-02 | aws_efs_file_system.primary | count=var.enable_efs ? 1 : 0 | no | 아이콘/서비스 | storage-access.tf:63 |
| OPT-02 | aws_efs_mount_target.primary | for_each=var.enable_efs ? { | no | 아이콘/서비스 | storage-access.tf:71 |
| DR-07 | aws_security_group.dr_efs | count=local.enable_dr_runtime && var.enable_efs ? 1 : 0 | no | 보안 경계/관계 | storage-access.tf:81 |
| DR-07 | aws_efs_file_system.dr | count=local.enable_dr_runtime && var.enable_efs ? 1 : 0 | no | 아이콘/서비스 | storage-access.tf:105 |
| DR-07 | aws_efs_mount_target.dr | for_each=local.enable_dr_runtime && var.enable_efs ? { | no | 아이콘/서비스 | storage-access.tf:113 |
| OPT-01 | aws_iam_role.primary_web_s3 | count=var.enable_web_s3_pod_identity ? 1 : 0 | no | 아이콘/서비스 | storage-access.tf:123 |
| OPT-01 | aws_iam_role_policy.primary_web_s3 | count=var.enable_web_s3_pod_identity ? 1 : 0 | no | 부속 설정/관계 | storage-access.tf:130 |
| OPT-01 | aws_eks_pod_identity_association.primary_web_s3 | count=var.enable_web_s3_pod_identity ? 1 : 0 | no | 부속 설정/관계 | storage-access.tf:143 |
| DR-07 | aws_iam_role.dr_web_s3 | count=var.enable_web_s3_pod_identity && local.enable_dr_runtime ? 1 : 0 | no | 아이콘/서비스 | storage-access.tf:152 |
| DR-07 | aws_iam_role_policy.dr_web_s3 | count=var.enable_web_s3_pod_identity && local.enable_dr_runtime ? 1 : 0 | no | 부속 설정/관계 | storage-access.tf:159 |
| DR-07 | aws_eks_pod_identity_association.dr_web_s3 | count=var.enable_web_s3_pod_identity && local.enable_dr_runtime ? 1 : 0 | no | 부속 설정/관계 | storage-access.tf:172 |
| DATA-02 | aws_s3_bucket.primary | always | yes | 아이콘/서비스 | storage-observability.tf:1 |
| DR-05 | aws_s3_bucket.dr | count=local.enable_dr_runtime ? 1 : 0 | no | 아이콘/서비스 | storage-observability.tf:7 |
| DATA-02 | aws_s3_bucket_versioning.primary | always | yes | 부속 설정/관계 | storage-observability.tf:14 |
| DR-05 | aws_s3_bucket_versioning.dr | count=local.enable_dr_runtime ? 1 : 0 | no | 부속 설정/관계 | storage-observability.tf:20 |
| DATA-02 | aws_s3_bucket_server_side_encryption_configuration.primary | always | yes | 부속 설정/관계 | storage-observability.tf:27 |
| DR-05 | aws_s3_bucket_server_side_encryption_configuration.dr | count=local.enable_dr_runtime ? 1 : 0 | no | 부속 설정/관계 | storage-observability.tf:37 |
| DATA-02 | aws_s3_bucket_public_access_block.primary | always | yes | 부속 설정/관계 | storage-observability.tf:48 |
| DR-05 | aws_s3_bucket_public_access_block.dr | count=local.enable_dr_runtime ? 1 : 0 | no | 부속 설정/관계 | storage-observability.tf:57 |
| DR-05 | aws_iam_role.s3_replication | count=local.enable_dr_runtime ? 1 : 0 | no | 아이콘/서비스 | storage-observability.tf:67 |
| DR-05 | aws_iam_role_policy.s3_replication | count=local.enable_dr_runtime ? 1 : 0 | no | 부속 설정/관계 | storage-observability.tf:77 |
| DR-05 | aws_s3_bucket_replication_configuration.primary_to_dr | count=local.enable_dr_runtime ? 1 : 0 | no | 아이콘/서비스 | storage-observability.tf:91 |
| RUN-12 | helm_release.primary_web_target_group_binding | count=var.manage_addons_via_local_helm ? 1 : 0 | no | 조건부 EKS 컴포넌트 | target-group-binding.tf:1 |
| DR-07 | helm_release.dr_web_target_group_binding | count=local.enable_dr_runtime && var.manage_addons_via_local_helm ? 1 : 0 | no | 조건부 EKS 컴포넌트 | target-group-binding.tf:23 |

## Module Coverage

| Logical ID | Module address | Condition | State expansion | Source |
|---|---|---|---|---|
| RUN-08 | module.primary_aws_lb_controller_pod_identity | always | yes | cluster-controllers.tf:1 |
| DR-02 | module.dr_aws_lb_controller_pod_identity | count=local.enable_dr_runtime ? 1 : 0 | no | cluster-controllers.tf:18 |
| RUN-09 | module.primary_external_dns_pod_identity | count=local.domain_name != "" ? 1 : 0 | yes | cluster-controllers.tf:94 |
| DR-07 | module.dr_external_dns_pod_identity | count=local.enable_dr_runtime && var.enable_dr_external_dns && local.domain_name != "" ? 1 : 0 | no | cluster-controllers.tf:115 |
| RUN-03 | module.primary_eks | always | yes | eks.tf:1 |
| DR-02 | module.dr_eks | count=local.enable_dr_runtime ? 1 : 0 | no | eks.tf:72 |
| RUN-07 | module.primary_karpenter | always | yes | eks.tf:144 |
| DR-02 | module.dr_karpenter | count=local.enable_dr_runtime ? 1 : 0 | no | eks.tf:156 |
| NET-01 | module.primary_vpc | always | yes | main.tf:135 |
| DR-01 | module.dr_vpc | count=local.enable_dr_runtime ? 1 : 0 | no | main.tf:165 |

## Data Source Coverage

| Logical ID | Data address | Condition | State address | Source |
|---|---|---|---|---|
| RUN-10 | aws_ssm_parameter.primary_al2023_ami | always | no | bastion.tf:1 |
| DR-06 | aws_ssm_parameter.dr_al2023_ami | count=local.enable_dr_runtime ? 1 : 0 | no | bastion.tf:6 |
| RUN-10 | aws_key_pair.primary_bastion | always | no | bastion.tf:12 |
| DR-06 | aws_key_pair.dr_bastion | count=local.enable_dr_runtime ? 1 : 0 | no | bastion.tf:17 |
| RUN-10 | aws_iam_policy_document.bastion_assume_role | always | no | bastion.tf:23 |
| FND-11 | aws_iam_policy_document.guardduty_eventbridge_assume | always | no | foundation/detection.tf:200 |
| FND-11 | aws_iam_policy_document.guardduty_eventbridge_publish | always | no | foundation/detection.tf:233 |
| FND-01 | aws_route53_zone.existing | count=var.domain_name == "" ? 0 : 1 | no | foundation/edge.tf:3 |
| META | aws_caller_identity.current | always | no | foundation/main.tf:41 |
| FND-03 | aws_iam_policy_document.github_actions_assume_role | always | no | foundation/main.tf:133 |
| FND-04 | aws_iam_policy_document.github_actions_ecr | always | no | foundation/main.tf:166 |
| FND-05 | aws_partition.current | always | no | foundation/observability.tf:1 |
| META | aws_caller_identity.current | always | no | main.tf:98 |
| FND-12 | terraform_remote_state.foundation | always | no | observability.tf:1 |
| RUN-01 | aws_ec2_managed_prefix_list.cloudfront | always | no | securitygroups.tf:1 |
| META | aws_iam_policy_document.pod_identity_assume_role | always | no | storage-access.tf:1 |

## Pending Non-Terraform Reads

- templates/install-cluster-addons.sh.tpl: 실제 SSM 설치 구성요소와 제어 흐름
- daily-up.ps1 / daily-down.ps1: 수명주기, DB bootstrap, evidence, Karpenter cleanup
- DVWA GitHub Actions / Argo CD / Helm templates: 배포와 실제 workload
- tools/Start-WafLiveViewer.ps1 및 Local Docker Grafana: 로컬 관측/대응 경계

## Placement Gate

Draw.io 배치는 BND → FND → GLB/NET → RUN/DATA → OBS → OPT/DR → NTF 순서로 진행한다. 각 단계 뒤 Direct Resource Coverage의 해당 Logical ID가 모두 시각 요소 또는 부모 라벨에 연결됐는지 확인한다.

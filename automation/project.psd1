@{
    SchemaVersion = 1

    Project = @{
        Name = 'aws-topology'
    }

    SessionSafety = @{
        Enabled              = $true
        SoftDeadlineHours    = 5
        MaxRuntimeHours      = 6
        RetryGraceHours      = 2
        RetryIntervalMinutes = 15
        TaskNamePrefix       = 'aws-topology-daily-session'
    }

    Applications = @(
        @{
            Name                      = 'dvwa'
            SourceRootDefault         = 'D:\DVWA'
            GitHubRepositoryDefault   = 'Unoh03/Uns-DVWA'
            WorkflowFile              = 'dvwa-ecr-gitops.yml'
            ValuesRelativePath        = 'deploy\dvwa\values.yaml'
            ArgoBootstrapRelativePath = 'scripts\bootstrap_argocd_repo.sh'
            ArgoApplication           = 'dvwa'
            Namespace                 = 'dvwa'
            WorkloadKind              = 'deployment'
            WorkloadName              = 'dvwa'
            PodSelector               = 'app.kubernetes.io/name=dvwa'
            UrlTerraformOutput        = 'application_url'

            Database = @{
                Enabled                = $true
                Type                   = 'MariaDbDvwa'
                TerraformOutput        = 'primary_db_bootstrap'
                BootstrapScript        = 'bootstrap-dvwa-runtime.sh'
                KubernetesSecretName   = 'dvwa-db'
            }
        }
    )

    Evidence = @{
        RootDefault         = '{UserHome}\Documents\aws-topology-evidence'
        HashAlgorithm       = 'SHA256'
        DefaultWindowMinutes = 60
        QueryPackRoot       = 'observability\queries'

        # These IDs are observability-pipeline validation candidates, not
        # team-approved attack or lab scenarios. Replace the mapping after the
        # team selects the project scenarios; the query files remain reusable.
        Queries = @(
            @{
                Name               = 'review-application-events'
                Type               = 'CloudWatchLogsInsights'
                ScenarioIds        = @('SOC-REVIEW')
                QueryFile          = 'cloudwatch\08_review_application_events.cwli'
                LogGroup           = '/aws/eks/{ProjectName}-primary/dvwa'
                Region             = 'Primary'
                Required           = $true
                MaxPollAttempts    = 30
                PollDelaySeconds   = 2
            }
            @{
                Name               = 'review-waf-requests'
                Type               = 'CloudWatchLogsInsights'
                ScenarioIds        = @('SOC-REVIEW')
                QueryFile          = 'cloudwatch\09_review_waf_requests.cwli'
                LogGroup           = 'aws-waf-logs-{ProjectName}-edge'
                Region             = 'Global'
                Required           = $true
                MaxPollAttempts    = 30
                PollDelaySeconds   = 2
            }
            @{
                Name               = 'review-kubernetes-sensitive-actions'
                Type               = 'CloudWatchLogsInsights'
                ScenarioIds        = @('SOC-REVIEW')
                QueryFile          = 'cloudwatch\03_kubectl_exec_and_secret_access.cwli'
                LogGroup           = '/aws/eks/{ProjectName}-primary/cluster'
                Region             = 'Primary'
                Required           = $false
                MaxPollAttempts    = 30
                PollDelaySeconds   = 2
            }
            @{
                Name               = 'review-cloudtrail-security-changes'
                Type               = 'CloudWatchLogsInsights'
                ScenarioIds        = @('SOC-REVIEW')
                QueryFile          = 'cloudwatch\04_cloudtrail_security_changes.cwli'
                LogGroup           = '/aws/cloudtrail/{ProjectName}-security'
                Region             = 'Primary'
                Required           = $false
                DeliveryGraceMinutes = 5
                EventTimeField     = 'event_time'
                MaxPollAttempts    = 30
                PollDelaySeconds   = 2
            }
            @{
                Name               = 'web-login-failures'
                Type               = 'CloudWatchLogsInsights'
                ScenarioIds        = @('WEB-01')
                QueryFile          = 'cloudwatch\01_repeated_login_failures.cwli'
                LogGroup           = '/aws/eks/{ProjectName}-primary/dvwa'
                Region             = 'Primary'
                Required           = $true
                MaxPollAttempts    = 30
                PollDelaySeconds   = 2
            }
            @{
                Name               = 'web-waf-count'
                Type               = 'CloudWatchLogsInsights'
                ScenarioIds        = @('WEB-01')
                QueryFile          = 'cloudwatch\02_waf_count_matches.cwli'
                LogGroup           = 'aws-waf-logs-{ProjectName}-edge'
                Region             = 'Global'
                Required           = $true
                MaxPollAttempts    = 30
                PollDelaySeconds   = 2
            }
            @{
                Name               = 'web-waf-block'
                Type               = 'CloudWatchLogsInsights'
                ScenarioIds        = @('WEB-01')
                QueryFile          = 'cloudwatch\06_waf_login_rate_limit.cwli'
                LogGroup           = 'aws-waf-logs-{ProjectName}-edge'
                Region             = 'Global'
                Required           = $true
                MaxPollAttempts    = 30
                PollDelaySeconds   = 2
            }
            @{
                Name               = 'iam-kubernetes-exec'
                Type               = 'CloudWatchLogsInsights'
                ScenarioIds        = @('IAM-01')
                QueryFile          = 'cloudwatch\03_kubectl_exec_and_secret_access.cwli'
                LogGroup           = '/aws/eks/{ProjectName}-primary/cluster'
                Region             = 'Primary'
                Required           = $true
                MaxPollAttempts    = 30
                PollDelaySeconds   = 2
            }
            @{
                Name               = 'iam-pod-identity-s3'
                Type               = 'CloudWatchLogsInsights'
                ScenarioIds        = @('IAM-01')
                QueryFile          = 'cloudwatch\07_pod_identity_and_s3_activity.cwli'
                LogGroup           = '/aws/cloudtrail/{ProjectName}-security'
                Region             = 'Primary'
                Required           = $true
                DeliveryGraceMinutes = 5
                EventTimeField     = 'eventTime'
                MaxPollAttempts    = 30
                PollDelaySeconds   = 2
            }
            @{
                Name                 = 'capital-one-validation-getobject'
                Type                 = 'CloudWatchLogsInsights'
                ScenarioIds          = @('CAPITAL-ONE')
                QueryFile            = 'cloudwatch\13_capital_one_validation_getobject.cwli'
                LogGroup             = '/aws/cloudtrail/{ProjectName}-security'
                Region               = 'Primary'
                Required             = $true
                DeliveryGraceMinutes = 10
                EventTimeField       = 'event_time'
                MaxPollAttempts      = 60
                PollDelaySeconds     = 5
                MinimumRows          = 1
                MaxDeliveryAttempts  = 6
                DeliveryRetryDelaySeconds = 10
            }
            @{
                Name               = 't1-waf-http-https'
                Type               = 'CloudWatchLogsInsights'
                ScenarioIds        = @('T1')
                QueryFile          = 'cloudwatch\10_t1_waf_requests.cwli'
                LogGroup           = 'aws-waf-logs-{ProjectName}-edge'
                Region             = 'Global'
                Required           = $true
                MaxPollAttempts    = 30
                PollDelaySeconds   = 2
            }
            @{
                Name               = 't1-application-http-https'
                Type               = 'CloudWatchLogsInsights'
                ScenarioIds        = @('T1')
                QueryFile          = 'cloudwatch\11_t1_application_requests.cwli'
                LogGroup           = '/aws/eks/{ProjectName}-primary/dvwa'
                Region             = 'Primary'
                Required           = $true
                MaxPollAttempts    = 30
                PollDelaySeconds   = 2
            }
            @{
                Name               = 'f2-guardduty-findings'
                Type               = 'CloudWatchLogsInsights'
                ScenarioIds        = @('F2')
                QueryFile          = 'cloudwatch\12_guardduty_findings.cwli'
                LogGroup           = '/aws/events/{ProjectName}-guardduty-findings'
                Region             = 'Primary'
                Required           = $true
                MaxPollAttempts    = 60
                PollDelaySeconds   = 5
            }
        )

        Review = @{
            ScenarioId    = 'SOC-REVIEW'
            MaxWindowHours = 6

            CloudWatchSources = @(
                @{
                    Name       = 'Application'
                    QueryName  = 'review-application-events'
                    Normalizer = 'Application'
                }
                @{
                    Name       = 'WAF'
                    QueryName  = 'review-waf-requests'
                    Normalizer = 'WAF'
                }
                @{
                    Name       = 'Kubernetes'
                    QueryName  = 'review-kubernetes-sensitive-actions'
                    Normalizer = 'Kubernetes'
                }
                @{
                    Name       = 'CloudTrail'
                    QueryName  = 'review-cloudtrail-security-changes'
                    Normalizer = 'CloudTrail'
                }
            )

            AthenaQueries = @(
                'cloudfront-trace'
                'alb-window'
                'alb-errors'
                'vpc-reject'
            )
        }

        Collectors = @(
            @{
                Name            = 'cloudtrail-management'
                Type            = 'S3Prefix'
                SourceRoot      = 'Foundation'
                TerraformOutput = 'security_log_bucket_name'
                Prefix          = 'AWSLogs/{AccountId}/CloudTrail/'
                Region          = 'Primary'
                Destination     = 'cloudtrail'
                FailurePolicy   = 'Warn'
                SkipIfMissing   = $true
                Required        = $false
                MaxAttempts     = 3
                RetryDelaySeconds = 2
            }
            @{
                Name            = 'cloudfront-access'
                Type                    = 'S3Prefix'
                SourceRoot              = 'Foundation'
                TerraformOutput         = 'security_log_bucket_name'
                Prefix                  = 'AWSLogs/{AccountId}/CloudFront/'
                Region                  = 'Primary'
                Destination             = 'cloudfront'
                FailurePolicy           = 'Warn'
                SkipIfMissing           = $true
                Required                = $false
                MaxAttempts             = 3
                RetryDelaySeconds       = 2
            }
            @{
                Name              = 'alb-primary-access'
                Type              = 'S3Prefix'
                SourceRoot        = 'Foundation'
                TerraformOutput   = 'security_log_bucket_name'
                Prefix            = 'alb/primary/AWSLogs/{AccountId}/elasticloadbalancing/{PrimaryRegion}/'
                Region            = 'Primary'
                Destination       = 'alb'
                FailurePolicy     = 'Warn'
                SkipIfMissing     = $true
                Required          = $false
                MaxAttempts       = 3
                RetryDelaySeconds = 2
            }
            @{
                Name              = 'vpc-reject'
                Type              = 'S3Prefix'
                SourceRoot        = 'Foundation'
                TerraformOutput   = 'security_log_bucket_name'
                Prefix            = 'vpc-flow/AWSLogs/{AccountId}/vpcflowlogs/{PrimaryRegion}/'
                Region            = 'Primary'
                Destination       = 'vpc-flow'
                FailurePolicy     = 'Warn'
                SkipIfMissing     = $true
                Required          = $false
                MaxAttempts       = 3
                RetryDelaySeconds = 2
            }
            @{
                Name              = 'eks-control-plane'
                Type              = 'CloudWatchLogs'
                SourceRoot        = 'Foundation'
                LogGroup          = '/aws/eks/{ProjectName}-primary/cluster'
                Region            = 'Primary'
                Destination       = 'eks-control-plane'
                FailurePolicy     = 'Warn'
                SkipIfMissing     = $true
                Required          = $false
                MaxAttempts       = 3
                RetryDelaySeconds = 2
            }
            @{
                Name              = 'waf-edge'
                Type              = 'CloudWatchLogs'
                SourceRoot        = 'Foundation'
                LogGroup          = 'aws-waf-logs-{ProjectName}-edge'
                Region            = 'Global'
                Destination       = 'waf'
                FailurePolicy     = 'Warn'
                SkipIfMissing     = $true
                Required          = $false
                MaxAttempts       = 3
                RetryDelaySeconds = 2
            }
            @{
                Name              = 'dvwa-application'
                Type              = 'CloudWatchLogs'
                SourceRoot        = 'Foundation'
                LogGroup          = '/aws/eks/{ProjectName}-primary/dvwa'
                Region            = 'Primary'
                Destination       = 'dvwa'
                FailurePolicy     = 'Warn'
                SkipIfMissing     = $true
                Required          = $true
                MaxAttempts       = 3
                RetryDelaySeconds = 2
            }
            @{
                Name              = 'dvwa-application-dr'
                Type              = 'CloudWatchLogs'
                SourceRoot        = 'Foundation'
                LogGroup          = '/aws/eks/{ProjectName}-dr/dvwa'
                Region            = 'Dr'
                Destination       = 'dvwa-dr'
                FailurePolicy     = 'Warn'
                SkipIfMissing     = $true
                Required          = $false
                MaxAttempts       = 3
                RetryDelaySeconds = 2
            }
        )
    }
}

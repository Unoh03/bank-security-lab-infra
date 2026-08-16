#!/bin/bash
set -euo pipefail

exec > >(tee -a /var/log/eks-cluster-addons.log) 2>&1
export HOME=/root
export AWS_REGION="${region}"
export AWS_DEFAULT_REGION="${region}"
export KUBECONFIG=/root/.kube/config

for attempt in $(seq 1 120); do
  if [ -f /var/lib/eks-bastion-bootstrap-complete ]; then
    break
  fi
  if [ "$attempt" -eq 120 ]; then
    echo "Bastion bootstrap did not complete within 20 minutes" >&2
    exit 1
  fi
  sleep 10
done

/usr/local/bin/configure-eks

helm upgrade --install karpenter oci://public.ecr.aws/karpenter/karpenter \
  --namespace kube-system \
  --version "${karpenter_chart_version}" \
  --set 'nodeSelector.workload=system' \
  --set 'settings.clusterName=${cluster_name}' \
  --set 'settings.clusterEndpoint=${cluster_endpoint}' \
  --set 'settings.interruptionQueue=${interruption_queue}' \
  --wait --timeout 10m

helm repo add eks https://aws.github.io/eks-charts --force-update
helm repo add external-dns https://kubernetes-sigs.github.io/external-dns/ --force-update
helm repo add argo https://argoproj.github.io/argo-helm --force-update
helm repo update

kubectl apply -f - <<'KARPENTER'
apiVersion: karpenter.k8s.aws/v1
kind: EC2NodeClass
metadata:
  name: default
spec:
  amiSelectorTerms:
    - alias: al2023@latest
  role: "${karpenter_node_role}"
  metadataOptions:
    httpEndpoint: "${metadata_http_endpoint}"
    httpProtocolIPv6: "${metadata_ipv6}"
    httpPutResponseHopLimit: ${metadata_hop_limit}
    httpTokens: "${metadata_http_tokens}"
  subnetSelectorTerms:
    - tags:
        karpenter.sh/discovery: "${cluster_name}"
  securityGroupSelectorTerms:
    - tags:
        karpenter.sh/discovery: "${cluster_name}"
  tags:
    Project: "${project_name}"
    ManagedBy: "Karpenter"
---
apiVersion: karpenter.sh/v1
kind: NodePool
metadata:
  name: default
spec:
  template:
    metadata:
      labels:
        workload: application
    spec:
      nodeClassRef:
        group: karpenter.k8s.aws
        kind: EC2NodeClass
        name: default
      requirements:
        - key: kubernetes.io/arch
          operator: In
          values: ["amd64"]
        - key: kubernetes.io/os
          operator: In
          values: ["linux"]
        - key: karpenter.sh/capacity-type
          operator: In
          values: ${capacity_types}
        - key: karpenter.k8s.aws/instance-category
          operator: In
          values: ["c", "m", "r", "t"]
        - key: karpenter.k8s.aws/instance-generation
          operator: Gt
          values: ["2"]
  limits:
    cpu: "${cpu_limit}"
  disruption:
    consolidationPolicy: WhenEmptyOrUnderutilized
    consolidateAfter: 1m
KARPENTER

if [ "${enable_fluent_bit}" = "true" ]; then
  cat >/tmp/aws-for-fluent-bit-values.yaml <<'FLUENTBIT'
serviceAccount:
  create: true
  name: aws-for-fluent-bit
filter:
  enabled: true
  mergeLog: "On"
  # Wazuh wraps the complete CloudWatch record below its own data field and
  # maps data.data as a keyword. Keep parsed application JSON under a distinct
  # object so Filebeat can index the record without a mapping conflict.
  mergeLogKey: "app_event"
  keepLog: "On"
additionalFilters: |
  [FILTER]
      Name    grep
      Match   kube.*
      Regex   $kubernetes['namespace_name'] ^${web_namespace}$
cloudWatchLogs:
  enabled: true
  match: "kube.*"
  region: "${region}"
  logGroupName: "${fluent_bit_log_group}"
  logStreamPrefix: "dvwa-"
  autoCreateGroup: false
resources:
  requests:
    cpu: 25m
    memory: 50Mi
  limits:
    memory: 150Mi
FLUENTBIT

  helm upgrade --install aws-for-fluent-bit eks/aws-for-fluent-bit \
    --namespace amazon-cloudwatch --create-namespace \
    --version "${fluent_bit_chart_version}" \
    --values /tmp/aws-for-fluent-bit-values.yaml \
    --wait --timeout 10m
  rm -f /tmp/aws-for-fluent-bit-values.yaml
fi

helm upgrade --install aws-load-balancer-controller eks/aws-load-balancer-controller \
  --namespace kube-system \
  --set 'clusterName=${cluster_name}' \
  --set 'region=${region}' \
  --set 'vpcId=${vpc_id}' \
  --set 'nodeSelector.workload=system' \
  --set 'serviceAccount.create=true' \
  --set 'serviceAccount.name=aws-load-balancer-controller' \
  --wait --timeout 10m

if [ "${enable_external_dns}" = "true" ]; then
  helm upgrade --install external-dns external-dns/external-dns \
    --namespace external-dns --create-namespace \
    --set 'provider.name=aws' \
    --set 'policy=upsert-only' \
    --set 'domainFilters[0]=${domain_name}' \
    --set 'txtOwnerId=${cluster_name}' \
    --set 'nodeSelector.workload=system' \
    --set 'serviceAccount.create=true' \
    --set 'serviceAccount.name=external-dns' \
    --wait --timeout 10m
fi

if [ "${enable_argocd}" = "true" ]; then
  helm upgrade --install argocd argo/argo-cd \
    --namespace argocd --create-namespace \
    --version "${argocd_chart_version}" \
    --set 'global.nodeSelector.workload=system' \
    --set 'redisSecretInit.nodeSelector.workload=application' \
    --set 'server.service.type=ClusterIP' \
    --set 'configs.params.server\.insecure=false' \
    --wait --timeout 10m
fi

kubectl create namespace "${web_namespace}" --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f - <<'TGB'
apiVersion: elbv2.k8s.aws/v1beta1
kind: TargetGroupBinding
metadata:
  name: web
  namespace: "${web_namespace}"
spec:
  serviceRef:
    name: "${web_service_name}"
    port: ${web_service_port}
  targetGroupARN: "${target_group_arn}"
  targetType: ip
  vpcID: "${vpc_id}"
TGB

kubectl get deployment -n kube-system karpenter aws-load-balancer-controller
if [ "${enable_fluent_bit}" = "true" ]; then
  kubectl get daemonset -n amazon-cloudwatch aws-for-fluent-bit
fi
if [ "${enable_argocd}" = "true" ]; then
  kubectl get deployment,statefulset -n argocd
fi
kubectl get targetgroupbinding -n "${web_namespace}" web
touch /var/lib/eks-cluster-addons-complete

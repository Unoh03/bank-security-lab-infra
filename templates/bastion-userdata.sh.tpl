#!/bin/bash
set -euo pipefail

exec > >(tee /var/log/eks-bastion-bootstrap.log | logger -t eks-bastion-bootstrap -s 2>/dev/console) 2>&1

dnf install -y git jq unzip tar gzip dnf-plugins-core mariadb105

# Install the newest kubectl patch for the EKS Kubernetes minor version.
KUBECTL_VERSION=$(curl -fsSL "https://dl.k8s.io/release/stable-${kubernetes_version}.txt")
curl -fsSL -o /usr/local/bin/kubectl "https://dl.k8s.io/release/$${KUBECTL_VERSION}/bin/linux/amd64/kubectl"
chmod 0755 /usr/local/bin/kubectl

# Helm is pinned so every regional bastion uses the same client version.
curl -fsSL -o /tmp/helm.tar.gz "https://get.helm.sh/helm-${helm_version}-linux-amd64.tar.gz"
tar -xzf /tmp/helm.tar.gz -C /tmp
install -m 0755 /tmp/linux-amd64/helm /usr/local/bin/helm
rm -rf /tmp/helm.tar.gz /tmp/linux-amd64

# Install Terraform from HashiCorp's RPM repository.
dnf config-manager --add-repo https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo
dnf install -y terraform

cat >/usr/local/bin/configure-eks <<'SCRIPT'
#!/bin/bash
set -euo pipefail
export AWS_REGION="${region}"
export AWS_DEFAULT_REGION="${region}"

for attempt in $(seq 1 30); do
  if aws eks describe-cluster --region "${region}" --name "${cluster_name}" >/dev/null 2>&1; then
    aws eks update-kubeconfig --region "${region}" --name "${cluster_name}" --alias "${cluster_name}"
    kubectl cluster-info
    kubectl get nodes
    exit 0
  fi
  sleep 10
done

echo "EKS cluster did not become accessible within 5 minutes" >&2
exit 1
SCRIPT
chmod 0755 /usr/local/bin/configure-eks

cat >/etc/profile.d/eks-admin.sh <<'EOF'
export AWS_REGION="${region}"
export AWS_DEFAULT_REGION="${region}"
# Empty profile makes Terraform and aws eks get-token use the EC2 instance role.
export TF_VAR_aws_profile=""
export KUBECONFIG=/home/ec2-user/.kube/config
EOF
chmod 0644 /etc/profile.d/eks-admin.sh

install -d -m 0700 -o ec2-user -g ec2-user /home/ec2-user/.kube
sudo -u ec2-user -H /usr/local/bin/configure-eks

touch /var/lib/eks-bastion-bootstrap-complete

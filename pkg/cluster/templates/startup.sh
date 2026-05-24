#!/bin/bash
set -euo pipefail

# Enable IP forwarding (Kubernetes Requirement)
modprobe -v br_netfilter
sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | tee -a /etc/sysctl.conf

sysctl --system

# Wrapper function to allow clean early-return without terminating the whole startup-script
install_dependencies() {
    if command -v kubeadm &> /dev/null; then
        echo "🚀 kubeadm is already installed. Skipping package installation steps."
        return 0
    fi

    echo "📦 kubeadm not found. Installing packages..."

    # Robust apt-get wrapper that retries on lock acquisition failure or network issues
    apt_get_retry() {
        local count=0
        local max_retries=5
        until apt-get "$@"; do
            if [ $count -eq $max_retries ]; then
                echo "❌ Failed to run apt-get after $max_retries attempts."
                return 1
            fi
            echo "🔒 apt-get was locked or failed. Retrying in 5 seconds ($count/$max_retries)..."
            sleep 5
            count=$((count + 1))
        done
    }

    # Install Containerd (Dynamic OS Detection)
    apt_get_retry update
    apt_get_retry install -y ca-certificates curl gnupg lsb-release

    install -m 0755 -d /etc/apt/keyrings

    . /etc/os-release
    DISTRO_ID=$ID
    if [ "$DISTRO_ID" != "debian" ] && [ "$DISTRO_ID" != "ubuntu" ]; then
        DISTRO_ID="ubuntu"
    fi

    curl -fsSL "https://download.docker.com/linux/$DISTRO_ID/gpg" | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg

    echo \
      "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$DISTRO_ID \
      "$VERSION_CODENAME" stable" | \
      tee /etc/apt/sources.list.d/docker.list > /dev/null

    apt_get_retry update
    apt_get_retry install -y containerd.io

    mkdir -p /etc/containerd
    containerd config default > /etc/containerd/config.toml
    sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
    systemctl restart containerd

    # Install Kubeadm/Kubelet/Kubectl
    # Version is injected by kingc based on config
    KUBERNETES_VERSION="{{ .KubernetesVersion }}"
    KUBERNETES_REPO_VERSION="{{ .KubernetesRepoVersion }}"

    curl -fsSL "https://pkgs.k8s.io/core:/stable:/${KUBERNETES_REPO_VERSION}/deb/Release.key" | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
    echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/${KUBERNETES_REPO_VERSION}/deb/ /" | sudo tee /etc/apt/sources.list.d/kubernetes.list

    apt_get_retry update
    apt_get_retry install -y kubelet kubeadm kubectl
    apt-mark hold kubelet kubeadm kubectl

    # Install cri-tools (crictl)
    curl -L "https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.36.0/crictl-v1.36.0-linux-amd64.tar.gz" -o crictl.tar.gz
    tar zxvf crictl.tar.gz -C /usr/local/bin
    rm -f crictl.tar.gz

    # Create crictl config
    echo "runtime-endpoint: unix:///run/containerd/containerd.sock" > /etc/crictl.yaml
}

# Execute package installations
install_dependencies
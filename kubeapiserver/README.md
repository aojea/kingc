# kube-apiserver image

This directory contains the necessary files to build a Docker image that runs both `etcd` and `kube-apiserver`.

## Overview

The image is designed to run `etcd` and `kube-apiserver` in a single container.
- `etcd` listens on a Unix socket at `/var/run/etcd/etcd.sock`.
- `kube-apiserver` is configured to talk to this local `etcd` socket.

## Building the Image

You can build the image using the project root `Makefile`:

```bash
# From the root of the repo
make image-kubeapiserver
```

Or manually using `docker build`:

```bash
docker build -t kingc-apiserver:latest .
```

### Build Arguments

- `KUBE_VERSION`: Version of kube-apiserver (default: `v1.35.0`).
- `ETCD_VERSION`: Version of etcd (default: `v3.5.12`).

## Runtime

The entrypoint script starts `etcd` in the background, waits for it to be ready, and then execs `kube-apiserver`.

### 1. Setup

Generate the necessary Service Account keys and token file. You can use `openssl` installed on your host or run a temporary container.

```bash
mkdir -p $(pwd)/data/pki

# Generate Service Account Key
if [ ! -f data/pki/sa.key ]; then
    openssl genrsa -out data/pki/sa.key 2048
    openssl rsa -in data/pki/sa.key -pubout -out data/pki/sa.pub
fi

# Generate Token Auth File
if [ ! -f data/pki/tokens.csv ]; then
    echo "admin-token,admin,uid,system:masters" > data/pki/tokens.csv
fi
```

### 2. Run

Mount the generated files and start the container.

```bash
docker run --rm -d \
  --name kingc-apiserver \
  -v $(pwd)/data:/data \
  -v $(pwd)/data/pki:/var/run/kubernetes \
  -p 6443:6443 \
  kingc-apiserver:latest \
  --secure-port=6443 \
  --service-cluster-ip-range=10.0.0.0/16 \
  --service-account-key-file=/var/run/kubernetes/sa.pub \
  --service-account-signing-key-file=/var/run/kubernetes/sa.key \
  --service-account-issuer=https://kubernetes.default.svc.cluster.local \
  --token-auth-file=/var/run/kubernetes/tokens.csv \
  --authorization-mode=Node,RBAC
```

### 3. Access with kubectl

You can generate a kubeconfig to access the server using the static token `admin-token`.

1. Create a minimal kubeconfig:

```bash
kubectl config set-cluster local-server \
  --server=https://127.0.0.1:6443 \
  --insecure-skip-tls-verify=true

kubectl config set-credentials admin \
  --token=admin-token

kubectl config set-context local-server \
  --cluster=local-server \
  --user=admin

kubectl config use-context local-server
```

2. Verify connection:

```bash
kubectl get nodes
kubectl get componentstatuses
```

# KINGC Kubernetes in Google Cloud

`kingc` is a tool for running vanilla Kubernetes clusters in Google Cloud Platform (GCP) using standard GCE VM instances.

It is primarily designed to provide a "Kind-like" experience for cloud-based development and CI, where real cloud integrations (LoadBalancers, PD CSI, Cross-Zone networking) are required.

Note: `kingc` is a bootstrapper, not a lifecycle manager. It does not maintain state files.

## Installation

### From Source

If you have go (1.21+) installed:

go install [github.com/your-username/kingc/cmd/kingc@latest](https://github.com/your-username/kingc/cmd/kingc@latest)


### From Release

Binary releases are available on the releases page.

## Quick Start

### Prerequisites

- Google Cloud SDK (gcloud) installed and authenticated.
- SSH Keys configured (gcloud compute config-ssh).
- Quota for at least 3 CPUs (if using defaults).

### Create a Cluster

#### Option A: Simple

This will provision a VPC, a Control Plane (n1-standard-2), and a Worker MIG (2 nodes).

```sh
$ kingc create cluster --name sandbox

Creating cluster "sandbox" ...
 ✓ Ensuring VPC network "sandbox-net" 
 ✓ Provisioning Load Balancer "sandbox-api" (34.x.x.x)
 ✓ Starting control-plane "sandbox-cp" 
 ✓ Bootstrapping Kubernetes (kubeadm init) ...
 ✓ Joining workers (Instance Group "sandbox-workers") ...
Set kubectl context to "kind-sandbox"
You can now use your cluster:
kubectl get nodes
```

#### Option B: Advanced (Config File)

Create kingc.yaml:

```yaml
version: v1alpha1
spec:
  # Region applies globally, per example to Networking and API LB
  region: us-central1
  
  controlPlane:
    name: cp
    zone: us-central1-a
    machineType: n1-standard-2

  workerGroups:
  - name: workers
    replicas: 2
    zone: us-central1-b # Can be different from CP
    machineType: n1-standard-2
```

Run: `kingc create --config kingc.yaml --name sandbox`


### Export Kubeconfig

The create command automatically merges the kubeconfig into ~/.kube/config (or $KUBECONFIG).

```sh
kubectl cluster-info --context kind-sandbox
```

### Deleting a Cluster

kingc is stateless. It discovers resources via the kingc-cluster: <name> label.

```sh
kingc delete cluster --name sandbox
```

## Architecture

`kingc` wraps kubeadm and gcloud to adhere to Kubernetes best practices on GCE without the complexity of managed services.

- Control Plane: A dedicated, unmanaged instance (allows for static IP attachment and etcd stability).

- API Server Endpoint: A TCP Passthrough Network Load Balancer (ensures the API server is accessible even if the VM is replaced).

- Workers: A Managed Instance Group (MIG).

- Cloud Provider: Configures cloud-provider-gcp (external) so Service type LoadBalancer works natively.

## Configuration

`kingc` uses a declarative YAML configuration file to define complex cluster topologies (e.g., multi-network setups).



# Where is the CNI?

Like Kind, `kingc` installs [kindnet](https://github.com/kubernetes-sigs/kindnet) by default, but users can disable the default CNI and install their own.

## Thanks

Special thanks to @bentheelder for creating [Kind](https://github.com/kubernetes-sigs/kind) and inspiring the design and philosophy of this project.

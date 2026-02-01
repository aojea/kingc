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

`kingc` uses a declarative YAML configuration file to define complex cluster topologies (e.g., GPU nodes, multi-network setups).

### A3 Ultra Example

High-performance GPU clusters require precise network isolation. `kingc` allows you to define the networking in region and place the nodes in a specific zone supported by A3 hardware.

```yaml
version: v1alpha1
spec:
  region: us-south1
  
  networks:
  # 1. Primary Network (Management)
  - name: primary-net
    subnets: [{name: primary-sub, cidr: 10.0.0.0/24}]

  # 2. GVNIC Network (Data Plane)
  - name: gvnic-net
    subnets: [{name: gvnic-sub, cidr: 192.168.0.0/24}]

  # 3. RDMA Network (HPC VPC)
  # This single VPC has a special profile enabling RoCE and contains 8 subnets
  - name: rdma-net
    profile: us-south1-b-vpc-roce # Required for A4
    subnets:
    - {name: rdma-sub-0, cidr: 192.168.1.0/24}
    - {name: rdma-sub-1, cidr: 192.168.2.0/24}
    - {name: rdma-sub-2, cidr: 192.168.3.0/24}
    - {name: rdma-sub-3, cidr: 192.168.4.0/24}
    - {name: rdma-sub-4, cidr: 192.168.5.0/24}
    - {name: rdma-sub-5, cidr: 192.168.6.0/24}
    - {name: rdma-sub-6, cidr: 192.168.7.0/24}
    - {name: rdma-sub-7, cidr: 192.168.8.0/24}

  controlPlane:
    name: control-plane
    zone: us-south1-b
    machineType: n1-standard-4

  workerGroups:
  - name: a4-pool
    replicas: 2
    zone: us-south1-b
    machineType: a4-highgpu-8g
    image: deeplearning-platform-release/common-cu123
    
    # Map NICs (Order: nic0=primary, nic1=gvnic, nic2-9=rdma)
    interfaces:
    - network: primary-net  # nic0
    - network: gvnic-net    # nic1
    
    # 8 RDMA interfaces attached to the SAME network but different subnets
    - {network: rdma-net, subnet: rdma-sub-0} # nic2
    - {network: rdma-net, subnet: rdma-sub-1} # nic3
    - {network: rdma-net, subnet: rdma-sub-2} # nic4
    - {network: rdma-net, subnet: rdma-sub-3} # nic5
    - {network: rdma-net, subnet: rdma-sub-4} # nic6
    - {network: rdma-net, subnet: rdma-sub-5} # nic7
    - {network: rdma-net, subnet: rdma-sub-6} # nic8
    - {network: rdma-net, subnet: rdma-sub-7} # nic9
```

## FAQ

### Why not just use GKE?

GKE is fantastic, but sometimes you need to test the control plane itself, have much more control over the cluster, or debug the Google Cloud Controller Manager. In those cases, `kingc` gives you more control over the cluster.

### Why not use Kops?

[Kops](https://kops.sigs.k8s.io/) is a powerful lifecycle management tool (upgrades, terraform integration, state storage). `kingc` is an ephemeral tool. It is designed to spin up a cluster in 3 minutes, run a test, and delete it or leverage other tools for lifecycle management.

### Where is the CNI?

Like Kind, `kingc` installs [kindnet](https://github.com/kubernetes-sigs/kindnet) by default, but users can disable the default CNI and install their own.

## Thanks

Special thanks to @bentheelder for creating [Kind](https://github.com/kubernetes-sigs/kind) and inspiring the design and philosophy of this project.

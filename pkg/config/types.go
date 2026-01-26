package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Cluster struct {
	Version  string   `yaml:"version"`
	Metadata Metadata `yaml:"metadata"`
	Spec     Spec     `yaml:"spec"`
}

type Metadata struct {
	Name string `yaml:"name"`
}

type Spec struct {
	// Region defines the default location for the Cluster API Load Balancer
	// and serves as the default region for subnets/nodes if not specified explicitly.
	Region string `yaml:"region"`

	// KubernetesVersion allows pinning a specific version (e.g. "v1.30.0")
	KubernetesVersion string `yaml:"kubernetesVersion"`

	FeatureGates  map[string]bool   `yaml:"featureGates"`
	RuntimeConfig map[string]string `yaml:"runtimeConfig"`

	Networks []NetworkSpec `yaml:"networks"`

	ControlPlane NodeGroup   `yaml:"controlPlane"`
	WorkerGroups []NodeGroup `yaml:"workerGroups"`

	KubeadmConfigPatches []string `yaml:"kubeadmConfigPatches"`
}

type NetworkSpec struct {
	Name    string       `yaml:"name"`
	MTU     int          `yaml:"mtu"`
	Profile string       `yaml:"profile"`
	Subnets []SubnetSpec `yaml:"subnets"`
}

type SubnetSpec struct {
	Name string `yaml:"name"`
	CIDR string `yaml:"cidr"`

	// Region is optional. If not set, defaults to the Cluster's Spec.Region.
	// This allows defining subnets in regions different from the control plane
	// (e.g. for cross-region worker pools).
	Region string `yaml:"region"`
}

type NodeGroup struct {
	Name string `yaml:"name"`

	// Topology Settings
	// If Zone is set, the group is Zonal (pinned to that zone).
	// If Zone is empty and Region is set, the group is Regional (e.g., Regional MIG for workers).
	// If both are empty, defaults to Cluster Region + default zone logic.
	Region string `yaml:"region"`
	Zone   string `yaml:"zone"`

	Replicas    int               `yaml:"replicas"`
	MachineType string            `yaml:"machineType"`
	Image       string            `yaml:"image"`
	DiskSizeGB  int               `yaml:"diskSizeGB"`
	Interfaces  []InterfaceSpec   `yaml:"interfaces"`
	KubeletArgs map[string]string `yaml:"kubeletArgs"`
}

type InterfaceSpec struct {
	Network string `yaml:"network"`
	Subnet  string `yaml:"subnet"`
}

func Default() *Cluster {
	c := &Cluster{
		Version: CurrentVersion,
	}
	c.Metadata.Name = DefaultClusterName
	c.Spec.Region = DefaultRegion
	c.Spec.KubernetesVersion = DefaultKubernetesVersion

	c.Spec.ControlPlane = NodeGroup{
		Name:        DefaultControlPlaneName,
		MachineType: DefaultControlPlaneMachineType,
		DiskSizeGB:  DefaultDiskSizeGB,
	}

	c.Spec.WorkerGroups = []NodeGroup{{
		Name:        DefaultWorkerGroupName,
		Replicas:    DefaultReplicas,
		MachineType: DefaultWorkerMachineType,
		DiskSizeGB:  DefaultDiskSizeGB,
	}}

	return c
}

func Load(path string) (*Cluster, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := Default()
	if err := yaml.Unmarshal(data, c); err != nil {
		return nil, err
	}

	c.SetDefaults()

	if err := c.Validate(); err != nil {
		return nil, err
	}

	return c, nil
}

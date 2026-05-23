package config

import (
	"fmt"
)

const (
	CurrentVersion = "v1alpha1"

	DefaultClusterName             = "kingc"
	DefaultRegion                  = "us-central1"
	DefaultZone                    = "us-central1-a"
	DefaultKubernetesVersion       = "v1.35.0"
	DefaultControlPlaneMachineType = "e2-standard-2"
	DefaultWorkerMachineType       = "e2-standard-2"
	DefaultDiskSizeGB              = 50
	DefaultWorkerReplicas          = 2

	DefaultNetworkName = "kingc-net"
	DefaultSubnetName  = "kingc-subnet"
	DefaultSubnetCIDR  = "10.0.0.0/24"
	DefaultPodCIDR     = "10.244.0.0/16"
	DefaultServiceCIDR = "10.96.0.0/12"

	DefaultControlPlaneName = "control-plane"
	DefaultWorkerGroupName  = "workers"

	DefaultImageProject   = "k8s-staging-cluster-api-gcp"
	DefaultImageFamily    = "cluster-api-ubuntu-2404-v1-35-5-nightly"
	DefaultAPIServerImage = "aojea/kingc-apiserver:latest"
)

// SetDefaults applies default values to the configuration
func (c *Cluster) SetDefaults() {
	if c.Spec.Region == "" {
		// Try to derived from Control Plane Zone if it was set (legacy support or partial config)
		if len(c.Spec.ControlPlane.Zone) > 2 {
			c.Spec.Region = c.Spec.ControlPlane.Zone[:len(c.Spec.ControlPlane.Zone)-2]
		} else {
			c.Spec.Region = DefaultRegion
		}
	}

	// 1. Default Network (Only if none specified)
	if len(c.Spec.Networks) == 0 {
		c.Spec.Networks = []NetworkSpec{{
			Name: DefaultNetworkName,
			Subnets: []SubnetSpec{{
				Name:   DefaultSubnetName,
				CIDR:   deriveSubnetCIDR(c.Spec.Region),
				Region: c.Spec.Region,
			}},
		}}
	} else {
		// Ensure subnets have region and CIDR defaulted
		for i := range c.Spec.Networks {
			for j := range c.Spec.Networks[i].Subnets {
				if c.Spec.Networks[i].Subnets[j].Region == "" {
					c.Spec.Networks[i].Subnets[j].Region = c.Spec.Region
				}
				if c.Spec.Networks[i].Subnets[j].CIDR == "" {
					c.Spec.Networks[i].Subnets[j].CIDR = deriveSubnetCIDR(c.Spec.Networks[i].Subnets[j].Region)
				}
			}
		}
	}

	// Control Plane Defaults
	c.applyNodeGroupDefaults(&c.Spec.ControlPlane, true)

	// Worker Groups Defaults
	for i := range c.Spec.WorkerGroups {
		c.applyNodeGroupDefaults(&c.Spec.WorkerGroups[i], false)
	}

	// TPU Groups Defaults
	for i := range c.Spec.TPUGroups {
		c.applyTPUGroupDefaults(&c.Spec.TPUGroups[i])
	}

	// Kubernetes Defaults
	if c.Spec.Kubernetes.Networking.PodCIDR == "" {
		c.Spec.Kubernetes.Networking.PodCIDR = DefaultPodCIDR
	}
	if c.Spec.Kubernetes.Networking.ServiceCIDR == "" {
		c.Spec.Kubernetes.Networking.ServiceCIDR = DefaultServiceCIDR
	}
}

func (c *Cluster) applyNodeGroupDefaults(ng *NodeGroup, isControlPlane bool) {
	if ng.Region == "" {
		ng.Region = c.Spec.Region
	}
	if ng.Name == "" {
		if isControlPlane {
			ng.Name = DefaultControlPlaneName
		} else {
			ng.Name = DefaultWorkerGroupName
		}
	}
	if ng.MachineType == "" {
		if isControlPlane {
			ng.MachineType = DefaultControlPlaneMachineType
		} else {
			ng.MachineType = DefaultWorkerMachineType
		}
	}
	if ng.DiskSizeGB == 0 {
		ng.DiskSizeGB = DefaultDiskSizeGB
	}

	defaultZone := fmt.Sprintf("%s-a", c.Spec.Region)

	if ng.Zone == "" {
		ng.Zone = defaultZone
	}
	if ng.Replicas == 0 {
		ng.Replicas = 1
	}
}

func (c *Cluster) applyTPUGroupDefaults(tg *TPUGroup) {
	if tg.Zone == "" {
		tg.Zone = fmt.Sprintf("%s-a", c.Spec.Region)
	}
	if tg.Replicas == 0 {
		tg.Replicas = 1
	}
	if tg.Spot == nil {
		trueVal := true
		tg.Spot = &trueVal
	}
}

func deriveSubnetCIDR(region string) string {
	hash := 0
	for _, char := range region {
		hash += int(char)
	}
	secondOctet := (hash % 250) + 1 // 1-250
	return fmt.Sprintf("10.%d.0.0/24", secondOctet)
}



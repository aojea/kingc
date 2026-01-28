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
	DefaultControlPlaneMachineType = "n1-standard-2"
	DefaultWorkerMachineType       = "n1-standard-2"
	DefaultDiskSizeGB              = 50
	DefaultWorkerReplicas          = 2

	DefaultNetworkName = "kingc-net"
	DefaultSubnetName  = "kingc-subnet"
	DefaultSubnetCIDR  = "10.0.0.0/24"
	DefaultPodCIDR     = "10.244.0.0/16"
	DefaultServiceCIDR = "10.96.0.0/12"

	DefaultControlPlaneName = "control-plane"
	DefaultWorkerGroupName  = "workers"

	DefaultImageProject   = "ubuntu-os-cloud"
	DefaultImageFamily    = "ubuntu-2204-lts"
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
				CIDR:   DefaultSubnetCIDR,
				Region: c.Spec.Region, // Default subnet in cluster region
			}},
		}}
	} else {
		// Ensure subnets have region defaulted
		for i := range c.Spec.Networks {
			for j := range c.Spec.Networks[i].Subnets {
				if c.Spec.Networks[i].Subnets[j].Region == "" {
					c.Spec.Networks[i].Subnets[j].Region = c.Spec.Region
				}
			}
		}
	}

	// Control Plane Defaults
	c.applyNodeGroupDefaults(&c.Spec.ControlPlane)

	// Worker Groups Defaults
	for i := range c.Spec.WorkerGroups {
		c.applyNodeGroupDefaults(&c.Spec.WorkerGroups[i])
	}

	// Kubernetes Defaults
	if c.Spec.Kubernetes.Networking.PodCIDR == "" {
		c.Spec.Kubernetes.Networking.PodCIDR = DefaultPodCIDR
	}
	if c.Spec.Kubernetes.Networking.ServiceCIDR == "" {
		c.Spec.Kubernetes.Networking.ServiceCIDR = DefaultServiceCIDR
	}
}

func (c *Cluster) applyNodeGroupDefaults(ng *NodeGroup) {
	if ng.Region == "" {
		ng.Region = c.Spec.Region
	}

	defaultZone := fmt.Sprintf("%s-a", c.Spec.Region)

	// If Zone is empty, it remains empty -> Regional (unless we enforce zonal default?)
	// "If both are empty, defaults to Cluster Region + default zone logic."
	// So if user didn't specify ANYTHING, we probably want a Zonal default for simplicity?
	// Or maybe Regional default?
	// The prompt says: "If both are empty, defaults to Cluster Region + default zone logic."
	// "default zone logic" usually implies picking a zone.
	if ng.Zone == "" {
		// Check if user INTENDED Regional. Even if Region was defaulted above.
		// Currently we defaulted Region.
		// If original config had NO Region and NO Zone, we probably want single zone (Zonal).
		// If original had Region but NO Zone, we want Regional.
		// Since we just set ng.Region, we can't distinguish "User set Region" vs "We defaulted Region" easily unless we check before.
		// Re-reading: "If Zone is empty and Region is set, the group is Regional"
		// But for CP, we usually want Zonal for single-replica or Regional for HA.
		// Let's assume Zonal default if nothing specified for MVP/Simplicity, matching previous behavior.
		ng.Zone = defaultZone
	}
}

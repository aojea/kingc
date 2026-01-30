package config

import (
	"fmt"
)

// Validate checks the configuration for errors
func (c *Cluster) Validate() error {
	if c.Version != CurrentVersion {
		return fmt.Errorf("unsupported config version: %s (expected %s)", c.Version, CurrentVersion)
	}

	if c.Spec.Region == "" {
		return fmt.Errorf("spec.region is required")
	}

	if err := c.validateNodeGroup("control-plane", c.Spec.ControlPlane); err != nil {
		return err
	}
	for _, grp := range c.Spec.WorkerGroups {
		if err := c.validateNodeGroup(grp.Name, grp); err != nil {
			return err
		}
	}

	if err := c.validateOIDC(); err != nil {
		return err
	}

	return nil
}

// validateNodeGroup checks a NodeGroup's network connectivity
func (c *Cluster) validateNodeGroup(name string, ng NodeGroup) error {
	if ng.Region == "" {
		return fmt.Errorf("node group '%s' has no region", name)
	}

	// If interfaces are explicit, check them
	if len(ng.Interfaces) > 0 {
		for _, iface := range ng.Interfaces {
			// Find network/subnet
			found := false
			for _, net := range c.Spec.Networks {
				if net.Name == iface.Network {
					for _, sub := range net.Subnets {
						if sub.Name == iface.Subnet {
							if sub.Region != ng.Region {
								return fmt.Errorf("node group '%s' (region %s) refers to subnet '%s' in region '%s'", name, ng.Region, sub.Name, sub.Region)
							}
							found = true
							break
						}
					}
				}
				if found {
					break
				}
			}
			if !found {
				return fmt.Errorf("node group '%s' refers to unknown network/subnet '%s/%s'", name, iface.Network, iface.Subnet)
			}
		}
	} else {
		// Implicit interface: must find AT LEAST ONE subnet in the group's region
		foundCompatibleSubnet := false
		for _, net := range c.Spec.Networks {
			for _, sub := range net.Subnets {
				if sub.Region == ng.Region {
					foundCompatibleSubnet = true
					break
				}
			}
			if foundCompatibleSubnet {
				break
			}
		}
		if !foundCompatibleSubnet {
			return fmt.Errorf("node group '%s' is in region '%s', but no subnets are defined for that region", name, ng.Region)
		}
	}
	return nil
}

func (c *Cluster) validateOIDC() error {
	oidc := c.Spec.Kubernetes.OIDC
	if oidc == nil {
		return nil
	}
	if oidc.ClientID == "" {
		return fmt.Errorf("oidc.clientID is required")
	}
	if oidc.IssuerURL == "" {
		return fmt.Errorf("oidc.issuerURL is required")
	}
	if oidc.UsernameClaim == "" {
		return fmt.Errorf("oidc.usernameClaim is required")
	}
	return nil
}

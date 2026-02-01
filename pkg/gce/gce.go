package gce

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type Client struct{}

func NewClient() *Client {
	return &Client{}
}

func (c *Client) Run(args ...string) (string, error) {
	cmd := exec.Command("gcloud", args...)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("command failed: gcloud %s: %v\nOutput: %s", strings.Join(args, " "), err, string(out))
	}
	return string(out), nil
}

func IsAlreadyExistsError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "already exists")
}

// RunJSON executes a gcloud command and unmarshals the output into the provided struct
func (c *Client) RunJSON(v interface{}, args ...string) error {
	args = append(args, "--format=json")
	out, err := c.Run(args...)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(out), v)
}

func (c *Client) CheckGcloud() error {
	_, err := exec.LookPath("gcloud")
	if err != nil {
		return fmt.Errorf("gcloud CLI not found in PATH")
	}
	return nil
}

func (c *Client) GetCurrentProject() (string, error) {
	out, err := c.Run("config", "get-value", "project")
	if err != nil {
		return "", err
	}
	proj := strings.TrimSpace(out)
	if proj == "" {
		return "", fmt.Errorf("no active project")
	}
	return proj, nil
}

// GetDefaultZone attempts to read compute/zone from gcloud config
func (c *Client) GetDefaultZone() string {
	out, err := c.Run("config", "get-value", "compute/zone")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// GetDefaultRegion attempts to read compute/region from gcloud config
func (c *Client) GetDefaultRegion() string {
	out, err := c.Run("config", "get-value", "compute/region")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func (c *Client) VerifyComputeAPI() error {
	var dump interface{}
	return c.RunJSON(&dump, "compute", "project-info", "describe")
}

func (c *Client) NetworkExists(name string) bool {
	_, err := c.Run("compute", "networks", "describe", name)
	return err == nil
}

func (c *Client) CreateNetwork(name string, autoMode bool, mtu int, profile string) error {
	mode := "custom"
	if autoMode {
		mode = "auto"
	}
	args := []string{"compute", "networks", "create", name, "--subnet-mode", mode}

	if mtu > 0 {
		args = append(args, "--mtu", fmt.Sprintf("%d", mtu))
	}

	if profile != "" {
		args = append(args, "--network-profile", profile)
	}

	_, err := c.Run(args...)
	return err
}

func (c *Client) CreateSubnet(name, network, region, rangeCIDR string) error {
	_, err := c.Run("compute", "networks", "subnets", "create", name,
		"--network", network,
		"--region", region,
		"--range", rangeCIDR)
	return err
}

func (c *Client) CreateFirewallRules(clusterName, network string) error {
	if _, err := c.Run("compute", "firewall-rules", "create", clusterName+"-internal",
		"--network", network, "--allow", "tcp,udp,icmp", "--source-ranges", "10.0.0.0/8,192.168.0.0/16,172.16.0.0/12"); err != nil && !IsAlreadyExistsError(err) {
		return err
	}

	if _, err := c.Run("compute", "firewall-rules", "create", clusterName+"-external",
		"--network", network, "--allow", "tcp:22,tcp:6443", "--source-ranges", "0.0.0.0/0"); err != nil && !IsAlreadyExistsError(err) {
		return err
	}
	return nil
}

func (c *Client) EnsureStaticIP(name, region string) (string, error) {
	// Define struct for decoding just what we need
	type Address struct {
		Address string `json:"address"`
	}
	var addr Address

	err := c.RunJSON(&addr, "compute", "addresses", "describe", name, "--region", region)
	if err == nil && addr.Address != "" {
		return addr.Address, nil
	}

	if _, err := c.Run("compute", "addresses", "create", name, "--region", region); err != nil && !IsAlreadyExistsError(err) {
		return "", err
	}

	err = c.RunJSON(&addr, "compute", "addresses", "describe", name, "--region", region)
	return addr.Address, err
}

func (c *Client) CreateInstance(name, zone, machineType, network, subnet, image, serviceAccount, startupScript, address string, tags []string) error {
	args := []string{
		"compute", "instances", "create", name,
		"--zone", zone,
		"--machine-type", machineType,
		"--network", network,
		"--subnet", subnet,
		"--image-family", image,
		"--image-project", "ubuntu-os-cloud",
		"--boot-disk-size", "50GB",
		"--scopes", "cloud-platform",
		"--tags", strings.Join(tags, ","),
		"--metadata-from-file", fmt.Sprintf("startup-script=%s", startupScript),
	}
	if address != "" {
		args = append(args, "--address", address)
	}
	if serviceAccount != "" {
		args = append(args, "--service-account", serviceAccount)
	}
	_, err := c.Run(args...)
	return err
}

type Address struct {
	Name    string `json:"name"`
	Region  string `json:"region"` // Global addresses might miss this or have it empty/global
	Address string `json:"address"`
}

func (c *Client) ListAddresses(filter string) ([]Address, error) {
	var addresses []Address
	err := c.RunJSON(&addresses, "compute", "addresses", "list", "--filter", filter)
	if err != nil {
		return nil, err
	}
	// Normalize?
	for i := range addresses {
		if addresses[i].Region != "" {
			parts := strings.Split(addresses[i].Region, "/")
			addresses[i].Region = parts[len(parts)-1]
		}
	}
	return addresses, nil
}

func (c *Client) DeleteAddress(name, region string) error {
	args := []string{"compute", "addresses", "delete", name, "--quiet"}
	if region != "" && region != "global" {
		args = append(args, "--region", region)
	} else {
		args = append(args, "--global")
	}
	_, err := c.Run(args...)
	return err
}

func (c *Client) SSH(instance, zone, command string) error {
	cmd := exec.Command("gcloud", "compute", "ssh", instance, "--zone", zone, "--command", command, "--", "-t", "-q")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (c *Client) RunSSHOutput(instance, zone, command string) (string, error) {
	return c.Run("compute", "ssh", instance, "--zone", zone, "--command", command, "--", "-q")
}

func (c *Client) SCP(localPath, remotePath, zone string) error {
	cmd := exec.Command("gcloud", "compute", "scp", localPath, remotePath, "--zone", zone)
	return cmd.Run()
}

func (c *Client) CreateInstanceTemplate(name, machineType string, networks, subnets []string, image, startupScript string, tags []string) error {
	args := []string{
		"compute", "instance-templates", "create", name,
		"--machine-type", machineType,
		"--image-family", image,
		"--image-project", "ubuntu-os-cloud",
		"--boot-disk-size", "50GB",
		"--scopes", "cloud-platform",
		"--tags", strings.Join(tags, ","),
		"--metadata-from-file", fmt.Sprintf("startup-script=%s", startupScript),
	}

	for i := 0; i < len(networks); i++ {
		nicArg := fmt.Sprintf("network=%s,subnet=%s", networks[i], subnets[i])
		if i == 0 {
			args = append(args, "--network-interface", nicArg)
		} else {
			args = append(args, "--network-interface", nicArg+",no-address")
		}
	}
	_, err := c.Run(args...)
	return err
}

func (c *Client) CreateMIG(name, template, zone string, size int) error {
	_, err := c.Run("compute", "instance-groups", "managed", "create", name,
		"--base-instance-name", name,
		"--template", template,
		"--size", fmt.Sprintf("%d", size),
		"--zone", zone)
	return err
}

func (c *Client) CreateUnmanagedInstanceGroup(name, zone string) error {
	// check if exists first? gcloud usually errors if exists
	_, err := c.Run("compute", "instance-groups", "unmanaged", "create", name, "--zone", zone)
	return err
}

func (c *Client) AddInstancesToGroup(group, zone string, instances ...string) error {
	args := []string{"compute", "instance-groups", "unmanaged", "add-instances", group, "--zone", zone, "--instances", strings.Join(instances, ",")}
	_, err := c.Run(args...)
	return err
}

func (c *Client) CreateRegionHealthCheck(name, region string) error {
	_, err := c.Run("compute", "health-checks", "create", "tcp", name, "--region", region, "--port", "6443")
	return err
}

func (c *Client) CreateRegionBackendService(name, region, healthCheck string) error {
	_, err := c.Run("compute", "backend-services", "create", name, "--protocol", "TCP", "--health-checks", healthCheck, "--health-checks-region", region, "--region", region, "--load-balancing-scheme", "EXTERNAL")
	return err
}

func (c *Client) AddRegionBackend(service, region, group, groupZone string) error {
	_, err := c.Run("compute", "backend-services", "add-backend", service, "--region", region, "--instance-group", group, "--instance-group-zone", groupZone)
	return err
}

func (c *Client) CreateRegionForwardingRule(name, region, service, address string) error {
	_, err := c.Run("compute", "forwarding-rules", "create", name, "--region", region, "--backend-service", service, "--address", address, "--ports", "6443")
	return err
}

func (c *Client) DeleteRegionForwardingRule(name, region string) error {
	_, err := c.Run("compute", "forwarding-rules", "delete", name, "--region", region, "--quiet")
	return err
}

func (c *Client) DeleteRegionBackendService(name, region string) error {
	_, err := c.Run("compute", "backend-services", "delete", name, "--region", region, "--quiet")
	return err
}

func (c *Client) DeleteRegionHealthCheck(name, region string) error {
	_, err := c.Run("compute", "health-checks", "delete", name, "--region", region, "--quiet")
	return err
}

func (c *Client) DeleteUnmanagedInstanceGroup(name, zone string) error {
	_, err := c.Run("compute", "instance-groups", "unmanaged", "delete", name, "--zone", zone, "--quiet")
	return err
}

type Instance struct {
	Name string `json:"name"`
	Zone string `json:"zone"`
}

func (c *Client) ListInstances(tags []string) ([]Instance, error) {
	var filter []string
	for _, t := range tags {
		filter = append(filter, fmt.Sprintf("tags.items=%s", t))
	}
	filterStr := strings.Join(filter, " AND ")

	var instances []Instance
	// We need to parse zone from the full URL e.g. "projects/p/zones/z/instances/name" or just "zones/z"
	// gcloud json output for List usually gives full selfLink or localized zone name.
	// Let's check "zone" field in output.
	err := c.RunJSON(&instances, "compute", "instances", "list", "--filter", filterStr)
	if err != nil {
		return nil, err
	}

	// Normalize Zone names (sometimes they come as URLs)
	for i := range instances {
		// zone often looks like "https://www.googleapis.com/compute/v1/projects/PROJ/zones/us-central1-a"
		parts := strings.Split(instances[i].Zone, "/")
		instances[i].Zone = parts[len(parts)-1]
	}
	return instances, nil
}

package gce

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/aojea/kingc/pkg/config"
)

type Client struct {
	Verbosity     string
	Quiet         bool
	NoUserOutput  bool
	Configuration string
}

type ClientOption func(*Client)

func WithVerbosity(v string) ClientOption {
	return func(c *Client) {
		c.Verbosity = v
	}
}

func WithQuiet(q bool) ClientOption {
	return func(c *Client) {
		c.Quiet = q
	}
}

func WithNoUserOutput(n bool) ClientOption {
	return func(c *Client) {
		c.NoUserOutput = n
	}
}

func WithConfiguration(cfg string) ClientOption {
	return func(c *Client) {
		c.Configuration = cfg
	}
}

func NewClient(opts ...ClientOption) *Client {
	c := &Client{}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *Client) argsWithVerbosity(args []string) []string {
	// Prepend configuration so it applies globally
	var prefix []string
	if c.Configuration != "" {
		prefix = append(prefix, "--configuration", c.Configuration)
	}
	// Append verbosity flags
	if c.Verbosity != "" {
		args = append(args, "--verbosity", c.Verbosity)
	}
	if c.Quiet {
		args = append(args, "--quiet")
	}
	if c.NoUserOutput {
		args = append(args, "--no-user-output-enabled")
	}
	return append(prefix, args...)
}

func (c *Client) Run(ctx context.Context, args ...string) (string, error) {
	args = c.argsWithVerbosity(args)
	cmd := exec.CommandContext(ctx, "gcloud", args...)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("command failed: gcloud %s: %v\nOutput: %s", strings.Join(args, " "), err, string(out))
	}
	return string(out), nil
}

// RunQuiet executes a command and returns only its stdout.
// Stderr is ignored/discarded to prevent pollution of JSON output with warnings,
// UNLESS verbosity is requested, in which case we stream Stderr to os.Stderr.
func (c *Client) RunQuiet(ctx context.Context, args ...string) (string, error) {
	args = c.argsWithVerbosity(args)
	cmd := exec.CommandContext(ctx, "gcloud", args...)
	cmd.Env = os.Environ()

	// We only want Stdout for the return value
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	// If Verbosity is set (and not "none"), we likely want to see logs (stderr) for debugging.
	// RunQuiet is typically used for JSON commands where we parse stdout.
	// If we mix stderr into stdout, JSON parsing fails.
	// So we must separate them.
	if c.Verbosity != "" && c.Verbosity != "none" {
		cmd.Stderr = os.Stderr
	} else {
		// Discard stderr by default or if quiet?
		// RunQuiet implies we don't want noise.
		// But if error happens, we want to know why.
		// The original implementation just discarded stderr via cmd.Output() (which captures stdout only).
		// We'll mimic that unless verbosity is explicitly enabled.
	}

	err := cmd.Run()
	if err != nil {
		// If we failed, strict return error.
		// If we were piping stderr to os.Stderr, user sees it.
		// If not, maybe we should include it in error?
		// But we didn't capture it if we didn't pipe it or capture it.
		// Let's rely on gcloud --verbosity providing enough info to stderr if connected.
		return "", fmt.Errorf("command failed: gcloud %s: %v", strings.Join(args, " "), err)
	}
	return stdout.String(), nil
}

// RunJSON executes a gcloud command and unmarshals the output into the provided struct
func (c *Client) RunJSON(ctx context.Context, v interface{}, args ...string) error {
	args = append(args, "--format=json")
	out, err := c.RunQuiet(ctx, args...)
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

func (c *Client) GetCurrentProject(ctx context.Context) (string, error) {
	out, err := c.Run(ctx, "config", "get-value", "project")
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
func (c *Client) GetDefaultZone(ctx context.Context) string {
	out, err := c.Run(ctx, "config", "get-value", "compute/zone")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// GetDefaultRegion attempts to read compute/region from gcloud config
func (c *Client) GetDefaultRegion(ctx context.Context) string {
	out, err := c.Run(ctx, "config", "get-value", "compute/region")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func (c *Client) VerifyComputeAPI(ctx context.Context) error {
	var dump interface{}
	return c.RunJSON(ctx, &dump, "compute", "project-info", "describe")
}

func (c *Client) NetworkExists(ctx context.Context, name string) bool {
	_, err := c.Run(ctx, "compute", "networks", "describe", name)
	return err == nil
}

func (c *Client) CreateNetwork(ctx context.Context, name string, autoMode bool, mtu int, profile string) error {
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

	_, err := c.Run(ctx, args...)
	return err
}

func (c *Client) CreateSubnet(ctx context.Context, name, network, region, rangeCIDR string) error {
	_, err := c.Run(ctx, "compute", "networks", "subnets", "create", name,
		"--network", network,
		"--region", region,
		"--range", rangeCIDR)
	return err
}

func (c *Client) CreateFirewallRules(ctx context.Context, clusterName, network string) error {
	if _, err := c.Run(ctx, "compute", "firewall-rules", "create", clusterName+"-internal",
		"--network", network, "--allow", "tcp,udp,icmp", "--source-ranges", "10.0.0.0/8,192.168.0.0/16,172.16.0.0/12"); err != nil && !IsAlreadyExistsError(err) {
		return err
	}

	if _, err := c.Run(ctx, "compute", "firewall-rules", "create", clusterName+"-external",
		"--network", network, "--allow", "tcp:22,tcp:6443", "--source-ranges", "0.0.0.0/0"); err != nil && !IsAlreadyExistsError(err) {
		return err
	}
	return nil
}

func (c *Client) EnsureStaticIP(ctx context.Context, name, region string) (string, error) {
	// Define struct for decoding just what we need
	type Address struct {
		Address string `json:"address"`
	}
	var addr Address

	err := c.RunJSON(ctx, &addr, "compute", "addresses", "describe", name, "--region", region)
	if err == nil && addr.Address != "" {
		return addr.Address, nil
	}

	if _, err := c.Run(ctx, "compute", "addresses", "create", name, "--region", region); err != nil && !IsAlreadyExistsError(err) {
		return "", err
	}

	err = c.RunJSON(ctx, &addr, "compute", "addresses", "describe", name, "--region", region)
	return addr.Address, err
}

func (c *Client) CreateInstance(ctx context.Context, name, zone, machineType, network, subnet, image, serviceAccount, startupScript, address string, tags []string) error {
	args := []string{
		"compute", "instances", "create", name,
		"--zone", zone,
		"--machine-type", machineType,
		"--network", network,
		"--subnet", subnet,
		"--image-family", image,
		"--image-project", config.DefaultImageProject,
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
	_, err := c.Run(ctx, args...)
	return err
}

type Address struct {
	Name    string `json:"name"`
	Region  string `json:"region"` // Global addresses might miss this or have it empty/global
	Address string `json:"address"`
}

func (c *Client) ListAddresses(ctx context.Context, filter string) ([]Address, error) {
	var addresses []Address
	err := c.RunJSON(ctx, &addresses, "compute", "addresses", "list", "--filter", filter)
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

func (c *Client) DeleteAddress(ctx context.Context, name, region string) error {
	args := []string{"compute", "addresses", "delete", name, "--quiet"}
	if region != "" && region != "global" {
		args = append(args, "--region", region)
	} else {
		args = append(args, "--global")
	}
	_, err := c.Run(ctx, args...)
	return err
}

func (c *Client) SSH(ctx context.Context, instance, zone, command string) error {
	cmd := exec.CommandContext(ctx, "gcloud", "compute", "ssh", instance, "--zone", zone, "--command", command, "--", "-t", "-q")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (c *Client) RunSSHOutput(ctx context.Context, instance, zone, command string) (string, error) {
	return c.Run(ctx, "compute", "ssh", instance, "--zone", zone, "--command", command, "--", "-q")
}

func (c *Client) SCP(ctx context.Context, localPath, remotePath, zone string) error {
	cmd := exec.CommandContext(ctx, "gcloud", "compute", "scp", localPath, remotePath, "--zone", zone)
	return cmd.Run()
}

func (c *Client) CreateInstanceTemplate(ctx context.Context, name, machineType string, networks, subnets []string, image, startupScript string, tags []string) error {
	args := []string{
		"compute", "instance-templates", "create", name,
		"--machine-type", machineType,
		"--image-family", image,
		"--image-project", config.DefaultImageProject,
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
	_, err := c.Run(ctx, args...)
	return err
}

func (c *Client) CreateMIG(ctx context.Context, name, template, zone string, size int) error {
	_, err := c.Run(ctx, "compute", "instance-groups", "managed", "create", name,
		"--base-instance-name", name,
		"--template", template,
		"--size", fmt.Sprintf("%d", size),
		"--zone", zone)
	return err
}

type Group struct {
	Name string `json:"name"`
	Zone string `json:"zone"`
}

func (c *Client) ListInstanceGroups(ctx context.Context, filter string) ([]Group, error) {
	var groups []Group
	// List both managed and unmanaged? Or just managed?
	// `gcloud compute instance-groups list` lists both.
	err := c.RunJSON(ctx, &groups, "compute", "instance-groups", "list", "--filter", filter)
	if err != nil {
		return nil, err
	}
	// Normalize zones
	for i := range groups {
		parts := strings.Split(groups[i].Zone, "/")
		groups[i].Zone = parts[len(parts)-1]
	}
	return groups, nil
}

func (c *Client) DeleteMIG(ctx context.Context, name, zone string) error {
	_, err := c.Run(ctx, "compute", "instance-groups", "managed", "delete", name, "--zone", zone, "--quiet")
	return err
}

func (c *Client) CreateUnmanagedInstanceGroup(ctx context.Context, name, zone string) error {
	// check if exists first? gcloud usually errors if exists
	_, err := c.Run(ctx, "compute", "instance-groups", "unmanaged", "create", name, "--zone", zone)
	return err
}

func (c *Client) AddInstancesToGroup(ctx context.Context, group, zone string, instances ...string) error {
	args := []string{"compute", "instance-groups", "unmanaged", "add-instances", group, "--zone", zone, "--instances", strings.Join(instances, ",")}
	_, err := c.Run(ctx, args...)
	return err
}

func (c *Client) CreateRegionHealthCheck(ctx context.Context, name, region string) error {
	_, err := c.Run(ctx, "compute", "health-checks", "create", "tcp", name, "--region", region, "--port", "6443")
	return err
}

func (c *Client) CreateRegionBackendService(ctx context.Context, name, region, healthCheck string) error {
	_, err := c.Run(ctx, "compute", "backend-services", "create", name, "--protocol", "TCP", "--health-checks", healthCheck, "--health-checks-region", region, "--region", region, "--load-balancing-scheme", "EXTERNAL")
	return err
}

type BackendService struct {
	Name   string `json:"name"`
	Region string `json:"region"`
}

func (c *Client) ListBackendServices(ctx context.Context, filter string) ([]BackendService, error) {
	var services []BackendService
	err := c.RunJSON(ctx, &services, "compute", "backend-services", "list", "--filter", filter)
	if err != nil {
		return nil, err
	}
	for i := range services {
		if services[i].Region != "" {
			parts := strings.Split(services[i].Region, "/")
			services[i].Region = parts[len(parts)-1]
		}
	}
	return services, nil
}

func (c *Client) AddRegionBackend(ctx context.Context, service, region, group, groupZone string) error {
	_, err := c.Run(ctx, "compute", "backend-services", "add-backend", service, "--region", region, "--instance-group", group, "--instance-group-zone", groupZone)
	return err
}

func (c *Client) CreateRegionForwardingRule(ctx context.Context, name, region, service, address string) error {
	_, err := c.Run(ctx, "compute", "forwarding-rules", "create", name, "--region", region, "--backend-service", service, "--address", address, "--ports", "6443")
	return err
}

type ForwardingRule struct {
	Name   string `json:"name"`
	Region string `json:"region"`
}

func (c *Client) ListForwardingRules(ctx context.Context, filter string) ([]ForwardingRule, error) {
	var rules []ForwardingRule
	err := c.RunJSON(ctx, &rules, "compute", "forwarding-rules", "list", "--filter", filter)
	if err != nil {
		return nil, err
	}
	for i := range rules {
		if rules[i].Region != "" {
			parts := strings.Split(rules[i].Region, "/")
			rules[i].Region = parts[len(parts)-1]
		}
	}
	return rules, nil
}

func (c *Client) DeleteRegionForwardingRule(ctx context.Context, name, region string) error {
	_, err := c.Run(ctx, "compute", "forwarding-rules", "delete", name, "--region", region, "--quiet")
	return err
}

func (c *Client) DeleteRegionBackendService(ctx context.Context, name, region string) error {
	_, err := c.Run(ctx, "compute", "backend-services", "delete", name, "--region", region, "--quiet")
	return err
}

func (c *Client) DeleteRegionHealthCheck(ctx context.Context, name, region string) error {
	_, err := c.Run(ctx, "compute", "health-checks", "delete", name, "--region", region, "--quiet")
	return err
}

func (c *Client) DeleteUnmanagedInstanceGroup(ctx context.Context, name, zone string) error {
	_, err := c.Run(ctx, "compute", "instance-groups", "unmanaged", "delete", name, "--zone", zone, "--quiet")
	return err
}

type Instance struct {
	Name string `json:"name"`
	Zone string `json:"zone"`
	Tags struct {
		Items []string `json:"items"`
	} `json:"tags"`
}

func (c *Client) ListInstances(ctx context.Context, tags []string) ([]Instance, error) {
	var filter []string
	for _, t := range tags {
		filter = append(filter, fmt.Sprintf("tags.items=%s", t))
	}
	filterStr := strings.Join(filter, " AND ")

	var instances []Instance
	// We need to parse zone from the full URL e.g. "projects/p/zones/z/instances/name" or just "zones/z"
	// gcloud json output for List usually gives full selfLink or localized zone name.
	// Let's check "zone" field in output.
	err := c.RunJSON(ctx, &instances, "compute", "instances", "list", "--filter", filterStr)
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

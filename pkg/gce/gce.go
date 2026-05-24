package gce

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"k8s.io/klog/v2"
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
	// Prepend verbosity flags (global flags should come before command args)
	if c.Verbosity != "" {
		prefix = append(prefix, "--verbosity", c.Verbosity)
	}
	if c.Quiet {
		prefix = append(prefix, "--quiet")
	}
	if c.NoUserOutput {
		prefix = append(prefix, "--no-user-output-enabled")
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
// Stderr is ignored/discarded to prevent pollution of JSON output with warnings.
func (c *Client) RunQuiet(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "gcloud", args...)
	cmd.Env = os.Environ()
	// We only want Stdout
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("command failed: gcloud %s: %v", strings.Join(args, " "), err)
	}
	return string(out), nil
}

func (c *Client) CheckServicesEnabled(ctx context.Context, services []string) error {
	// Check if services are enabled.
	// We use 'gcloud services list --enabled --filter="config.name:(...)"' to verify.
	// Construct filter string: config.name:(service1 OR service2 OR ...)
	// Actually gcloud filter syntax for multiple values: config.name=(s1,s2,...)
	if len(services) == 0 {
		return nil
	}

	joinedServices := strings.Join(services, ",")
	filter := fmt.Sprintf("config.name=(%s)", joinedServices)

	type Service struct {
		Config struct {
			Name string `json:"name"`
		} `json:"config"`
	}
	var enabledServices []Service

	// We use RunJSON to get structured output
	// Note: gcloud services list might require Service Usage API (serviceusage.googleapis.com)
	// If that's not enabled, this might fail. But if it fails we can probably assume something is wrong.
	if err := c.RunJSON(ctx, &enabledServices, "services", "list", "--enabled", "--filter", filter); err != nil {
		return fmt.Errorf("failed to list enabled services: %v", err)
	}

	enabledMap := make(map[string]bool)
	for _, s := range enabledServices {
		enabledMap[s.Config.Name] = true
	}

	var missing []string
	for _, s := range services {
		if !enabledMap[s] {
			missing = append(missing, s)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("the following required Google Cloud APIs are not enabled: %s. Please enable them via 'gcloud services enable ...' or the Cloud Console", strings.Join(missing, ", "))
	}

	return nil
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
	out, err := c.RunQuiet(ctx, "config", "get-value", "project")
	if err != nil {
		return "", err
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	proj := strings.TrimSpace(lines[len(lines)-1])
	if proj == "" {
		return "", fmt.Errorf("no active project")
	}
	return proj, nil
}

// GetDefaultZone attempts to read compute/zone from gcloud config
func (c *Client) GetDefaultZone(ctx context.Context) string {
	out, err := c.RunQuiet(ctx, "config", "get-value", "compute/zone")
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// GetDefaultRegion attempts to read compute/region from gcloud config
func (c *Client) GetDefaultRegion(ctx context.Context) string {
	out, err := c.RunQuiet(ctx, "config", "get-value", "compute/region")
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

func (c *Client) VerifyComputeAPI(ctx context.Context) error {
	var dump interface{}
	return c.RunJSON(ctx, &dump, "compute", "project-info", "describe")
}

func (c *Client) NetworkExists(ctx context.Context, name string) bool {
	_, err := c.Run(ctx, "compute", "networks", "describe", name)
	return err == nil
}

func (c *Client) SubnetExists(ctx context.Context, name, region string) bool {
	_, err := c.RunQuiet(ctx, "compute", "networks", "subnets", "describe", name, "--region", region)
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

func (c *Client) CreateFirewallRules(ctx context.Context, name, network string) error {
	if _, err := c.Run(ctx, "compute", "firewall-rules", "create", name+"-internal",
		"--network", network, "--allow", "tcp,udp,icmp", "--source-ranges", "10.0.0.0/8,192.168.0.0/16,172.16.0.0/12"); err != nil && !IsAlreadyExistsError(err) {
		return err
	}

	if _, err := c.Run(ctx, "compute", "firewall-rules", "create", name+"-external",
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

func (c *Client) DeleteStaticIP(ctx context.Context, name, region string) error {
	if _, err := c.Run(ctx, "compute", "addresses", "delete", name, "--region", region, "--quiet"); err != nil && !IsAlreadyExistsError(err) {
		return err
	}
	return nil
}

func (c *Client) CreateInstance(ctx context.Context, name, zone, machineType, network, subnet, imageProject, image, serviceAccount, startupScript, address, privateIP string, tags []string) error {
	args := []string{
		"compute", "instances", "create", name,
		"--zone", zone,
		"--machine-type", machineType,
		"--network", network,
		"--subnet", subnet,
		"--image", image,
		"--image-project", imageProject,
		"--boot-disk-size", "50GB",
		"--scopes", "cloud-platform",
		"--tags", strings.Join(tags, ","),
		"--metadata-from-file", fmt.Sprintf("startup-script=%s", startupScript),
	}
	if address != "" {
		args = append(args, "--address", address)
	}
	if privateIP != "" {
		args = append(args, "--private-network-ip", privateIP)
	}
	if serviceAccount != "" {
		args = append(args, "--service-account", serviceAccount)
	}
	_, err := c.Run(ctx, args...)
	return err
}

func (c *Client) DeleteInstance(ctx context.Context, name, zone string) error {
	_, err := c.Run(ctx, "compute", "instances", "delete", name, "--zone", zone, "--quiet")
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

func (c *Client) SSH(ctx context.Context, instance, zone string, cmd []string) error {
	// Attempt 1: Try with default SSH config (respects user settings/agents)
	args := []string{"compute", "ssh", instance, "--zone", zone}
	if len(cmd) > 0 {
		args = append(args, "--command", strings.Join(cmd, " "))
	}
	// We only care about error here, output is piped if Verbosity is set via Run
	_, err := c.Run(ctx, args...)
	if err == nil {
		return nil
	}

	// Attempt 2: Retry with config bypass if the first attempt failed
	// This handles cases like corp-ssh-helper prompts or bad proxy configs hanging/failing
	klog.V(2).Infof("SSH attempt 1 to %s failed (%v), retrying with -F /dev/null", instance, err)

	argsRetry := []string{"compute", "ssh", instance, "--zone", zone, "--ssh-flag=-F /dev/null"}
	if len(cmd) > 0 {
		argsRetry = append(argsRetry, "--command", strings.Join(cmd, " "))
	}

	_, err2 := c.Run(ctx, argsRetry...)
	if err2 == nil {
		klog.Warningf("SSH connection to %s succeeded only after bypassing local SSH config (-F /dev/null). Check your ~/.ssh/config for incompatibility.", instance)
		return nil
	}

	// Return combined error to help debugging
	return fmt.Errorf("ssh failed (default config: %v) (bypass config: %v)", err, err2)
}

func (c *Client) RunSSHOutput(ctx context.Context, instance, zone, command string) (string, error) {
	// Attempt 1
	out, err := c.RunQuiet(ctx, "compute", "ssh", instance, "--zone", zone, "--command", command, "--", "-q")
	if err == nil {
		return out, nil
	}

	// Attempt 2
	klog.V(2).Infof("RunSSHOutput attempt 1 to %s failed (%v), retrying with -F /dev/null", instance, err)
	out2, err2 := c.RunQuiet(ctx, "compute", "ssh", instance, "--zone", zone, "--ssh-flag=-F /dev/null", "--command", command, "--", "-q")
	if err2 == nil {
		klog.Warningf("SSH command to %s succeeded only after bypassing local SSH config (-F /dev/null).", instance)
		return out2, nil
	}

	return "", fmt.Errorf("ssh command failed (default: %v) (bypass: %v)", err, err2)
}

func (c *Client) RunSSHRaw(ctx context.Context, instance, zone string, cmd []string) ([]byte, error) {
	runRaw := func(args ...string) ([]byte, error) {
		klog.V(4).Infof("Running (raw): gcloud %s", strings.Join(args, " "))
		cCmd := exec.CommandContext(ctx, "gcloud", args...)
		// Capture stderr if verbose
		if c.Verbosity != "" && c.Verbosity != "none" {
			cCmd.Stderr = os.Stderr
		}
		return cCmd.Output()
	}

	// Attempt 1
	args := []string{"compute", "ssh", instance, "--zone", zone}
	if len(cmd) > 0 {
		args = append(args, "--command", strings.Join(cmd, " "))
	}
	out, err := runRaw(args...)
	if err == nil {
		return out, nil
	}

	// Attempt 2
	klog.V(2).Infof("RunSSHRaw attempt 1 to %s failed (%v), retrying with -F /dev/null", instance, err)
	argsRetry := []string{"compute", "ssh", instance, "--zone", zone, "--ssh-flag=-F /dev/null"}
	if len(cmd) > 0 {
		argsRetry = append(argsRetry, "--command", strings.Join(cmd, " "))
	}
	out2, err2 := runRaw(argsRetry...)
	if err2 == nil {
		klog.Warningf("SSH command to %s succeeded only after bypassing local SSH config (-F /dev/null).", instance)
		return out2, nil
	}
	return nil, fmt.Errorf("ssh raw command failed: %v (bypass attempt: %v)", err, err2)
}

func (c *Client) SCP(ctx context.Context, localPath, remotePath, zone string) error {
	cmd := exec.CommandContext(ctx, "gcloud", "compute", "scp", localPath, remotePath, "--zone", zone)
	return cmd.Run()
}

func (c *Client) CreateInstanceTemplate(ctx context.Context, name, machineType string, networks, subnets []string, imageProject, image, startupScript string, tags []string) error {
	args := []string{
		"compute", "instance-templates", "create", name,
		"--machine-type", machineType,
		"--image", image,
		"--image-project", imageProject,
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

func (c *Client) GetInternalIP(ctx context.Context, name, zone string) (string, error) {
	out, err := c.RunQuiet(ctx, "compute", "instances", "describe", name, "--zone", zone, "--format=value(networkInterfaces[0].networkIP)")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

func (c *Client) ImageExists(ctx context.Context, project, name string) bool {
	_, err := c.RunQuiet(ctx, "compute", "images", "describe", name, "--project", project)
	return err == nil
}

func (c *Client) CreateTPUVM(ctx context.Context, name, zone, accelType, runtimeVer string, network, subnetwork string, spot bool, startupScript string, tags []string) error {
	args := []string{
		"compute", "tpus", "tpu-vm", "create", name,
		"--zone", zone,
		"--accelerator-type", accelType,
		"--version", runtimeVer,
	}
	if network != "" {
		args = append(args, "--network", network)
	}
	if subnetwork != "" {
		args = append(args, "--subnetwork", subnetwork)
	}
	if spot {
		args = append(args, "--spot")
	}
	if len(tags) > 0 {
		args = append(args, "--tags", strings.Join(tags, ","))
	}
	if startupScript != "" {
		args = append(args, "--metadata-from-file", fmt.Sprintf("startup-script=%s", startupScript))
	}

	_, err := c.Run(ctx, args...)
	return err
}

func (c *Client) DeleteTPUVM(ctx context.Context, name, zone string) error {
	_, err := c.Run(ctx, "compute", "tpus", "tpu-vm", "delete", name, "--zone", zone, "--quiet")
	return err
}

func (c *Client) ListTPULocations(ctx context.Context) ([]string, error) {
	out, err := c.RunQuiet(ctx, "compute", "tpus", "locations", "list", "--format=value(locationId)")
	if err != nil {
		return nil, err
	}
	return strings.Fields(out), nil
}

func (c *Client) DescribeAcceleratorType(ctx context.Context, accelType, zone string) bool {
	_, err := c.RunQuiet(ctx, "compute", "tpus", "accelerator-types", "describe", accelType, "--zone", zone)
	return err == nil
}

func (c *Client) TPUVMSSH(ctx context.Context, name, zone string, cmd []string) error {
	args := []string{"compute", "tpus", "tpu-vm", "ssh", name, "--zone", zone}
	if len(cmd) > 0 {
		args = append(args, "--command", strings.Join(cmd, " "))
	}
	_, err := c.Run(ctx, args...)
	return err
}



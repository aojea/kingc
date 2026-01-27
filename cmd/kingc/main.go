package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/aojea/kingc/pkg/cluster"
	"github.com/aojea/kingc/pkg/config"
	"github.com/spf13/cobra"
	"k8s.io/klog/v2"
)

var (
	rootCmd = &cobra.Command{
		Use:   "kingc",
		Short: "Kubernetes IN Google Cloud",
		Long: `kingc creates and manages Kubernetes clusters on Google Cloud Platform.
It attempts to mimic the behavior and user experience of 'kind' but for GCE.`,
	}

	createCmd = &cobra.Command{
		Use:   "create",
		Short: "Creates one of [cluster]",
	}

	createClusterCmd = &cobra.Command{
		Use:   "cluster",
		Short: "Create a new Kubernetes cluster",
		Run:   runCreateCluster,
	}

	deleteCmd = &cobra.Command{
		Use:   "delete",
		Short: "Deletes one of [cluster]",
	}

	deleteClusterCmd = &cobra.Command{
		Use:   "cluster",
		Short: "Delete a cluster",
		Run:   runDeleteCluster,
	}

	getCmd = &cobra.Command{
		Use:   "get",
		Short: "Gets one of [clusters, nodes, kubeconfig]",
	}

	getClustersCmd = &cobra.Command{
		Use:   "clusters",
		Short: "List discovered clusters",
		Run:   runGetClusters,
	}

	getNodesCmd = &cobra.Command{
		Use:   "nodes",
		Short: "List nodes in a cluster",
		Run:   runGetNodes,
	}

	getKubeconfigCmd = &cobra.Command{
		Use:   "kubeconfig",
		Short: "Print cluster kubeconfig",
		Run:   runGetKubeconfig,
	}

	exportCmd = &cobra.Command{
		Use:   "export",
		Short: "Exports one of [logs]",
	}

	exportLogsCmd = &cobra.Command{
		Use:   "logs [output-dir]",
		Short: "Export logs to a directory",
		Args:  cobra.MaximumNArgs(1),
		Run:   runExportLogs,
	}

	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Prints the kingc CLI version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("kingc v0.1.0")
		},
	}
)

func init() {
	// Root flags
	rootCmd.PersistentFlags().AddGoFlagSet(flag.CommandLine)
	rootCmd.PersistentFlags().BoolP("quiet", "q", false, "silence all stderr output")

	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		quiet, _ := cmd.Flags().GetBool("quiet")
		if quiet {
			// Suppress klog output
			flag.Set("logtostderr", "false")
			flag.Set("stderrthreshold", "FATAL")
		}
	}

	// Create hierarchy
	rootCmd.AddCommand(createCmd)
	createCmd.AddCommand(createClusterCmd)

	rootCmd.AddCommand(deleteCmd)
	deleteCmd.AddCommand(deleteClusterCmd)

	rootCmd.AddCommand(getCmd)
	getCmd.AddCommand(getClustersCmd)
	getCmd.AddCommand(getNodesCmd)
	getCmd.AddCommand(getKubeconfigCmd)

	rootCmd.AddCommand(exportCmd)
	exportCmd.AddCommand(exportLogsCmd)

	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(completionCmd)

	// Create Cluster Flags
	createClusterCmd.Flags().String("config", "", "Path to a kingc.yaml config file")
	createClusterCmd.Flags().String("name", "kingc", "Cluster name")
	createClusterCmd.Flags().Bool("retain", false, "Retain resources on failure for debugging")

	// Delete Cluster Flags
	deleteClusterCmd.Flags().String("name", "kingc", "Cluster name")

	// Get Nodes Flags
	getNodesCmd.Flags().String("name", "kingc", "Cluster name")

	// Get Kubeconfig Flags
	getKubeconfigCmd.Flags().String("name", "kingc", "Cluster name")

	// Export Logs Flags
	exportLogsCmd.Flags().String("name", "kingc", "Cluster name")
}

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate completion script",
	Long: `To load completions:

Bash:
  $ source <(kingc completion bash)

Zsh:
  # If shell completion is not already enabled in your environment you will need
  # to enable it.  You can execute the following once:

  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

  # To load completions for each session, execute once:
  $ kingc completion zsh > "${fpath[1]}/_kingc"

  # You will need to start a new shell for this setup to take effect.

Fish:
  $ kingc completion fish | source

Powershell:
  PS> kingc completion powershell | Out-String | Invoke-Expression
`,
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	Run: func(cmd *cobra.Command, args []string) {
		switch args[0] {
		case "bash":
			cmd.Root().GenBashCompletion(os.Stdout)
		case "zsh":
			cmd.Root().GenZshCompletion(os.Stdout)
		case "fish":
			cmd.Root().GenFishCompletion(os.Stdout, true)
		case "powershell":
			cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
		}
	},
}

func main() {
	klog.InitFlags(nil)
	_ = flag.CommandLine.Set("logtostderr", "true")

	// Create context that cancels on SIGINT or SIGTERM
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		klog.Error(err)
		os.Exit(1)
	}
}

func runCreateCluster(cmd *cobra.Command, args []string) {
	configFile, _ := cmd.Flags().GetString("config")
	var cfg *config.Cluster
	var err error

	name, _ := cmd.Flags().GetString("name")
	if name == "" {
		klog.Fatalf("❌ Error: name is required")
	}

	if configFile != "" {
		cfg, err = config.Load(configFile)
		if err != nil {
			klog.Fatalf("❌ Error loading config: %v", err)
		}
	} else {
		// Use flags to build default config
		cfg = config.Default()
	}
	// override default name if specified
	if name != "kingc" {
		cfg.Metadata.Name = name
	}

	retain, _ := cmd.Flags().GetBool("retain")

	if err := cluster.NewManager().Create(cmd.Context(), cfg, retain); err != nil {
		// If the error was context cancelled, we might have already logged/cleaned up
		if cmd.Context().Err() != nil {
			// Don't fatal here if we already handled cleanup in Create
			klog.Exitf("❌ Operation cancelled: %v", err)
		}
		klog.Fatalf("❌ Error creating cluster: %v", err)
	}
}

func runDeleteCluster(cmd *cobra.Command, args []string) {
	name, _ := cmd.Flags().GetString("name")

	if err := cluster.NewManager().Delete(cmd.Context(), name); err != nil {
		klog.Fatalf("❌ Error deleting cluster: %v", err)
	}
}

func runGetClusters(cmd *cobra.Command, args []string) {
	clusters, err := cluster.NewManager().ListClusters(cmd.Context())
	if err != nil {
		klog.Fatalf("❌ Error listing clusters: %v", err)
	}
	for _, c := range clusters {
		fmt.Println(c)
	}
}

func runGetNodes(cmd *cobra.Command, args []string) {
	name, _ := cmd.Flags().GetString("name")
	nodes, err := cluster.NewManager().ListNodes(cmd.Context(), name)
	if err != nil {
		klog.Fatalf("❌ Error listing nodes for cluster %s: %v", name, err)
	}
	if len(nodes) == 0 {
		fmt.Printf("No nodes found for cluster '%s'\n", name)
		return
	}
	// Simple table output
	fmt.Printf("%-30s %-20s %-15s\n", "NAME", "ZONE", "STATUS")
	for _, n := range nodes {
		fmt.Printf("%-30s %-20s %-15s\n", n.Name, n.Zone, "RUNNING")
	}
}

func runGetKubeconfig(cmd *cobra.Command, args []string) {
	name, _ := cmd.Flags().GetString("name")
	kc, err := cluster.NewManager().GetKubeconfig(cmd.Context(), name)
	if err != nil {
		klog.Fatalf("❌ Error retrieving kubeconfig: %v", err)
	}
	fmt.Println(kc)
}

func runExportLogs(cmd *cobra.Command, args []string) {
	name, _ := cmd.Flags().GetString("name")
	outDir := "."
	if len(args) > 0 {
		outDir = args[0]
	}
	if err := cluster.NewManager().ExportLogs(cmd.Context(), name, outDir); err != nil {
		klog.Fatalf("❌ Error exporting logs: %v", err)
	}
	klog.Infof("✅ Logs exported to %s", outDir)
}

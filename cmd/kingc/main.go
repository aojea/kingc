package main

import (
	"os"

	"github.com/aojea/kingc/pkg/cluster"
	"github.com/aojea/kingc/pkg/config"
	"github.com/spf13/cobra"
	"k8s.io/klog/v2"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "kingc",
		Short: "Kubernetes IN Google Cloud",
	}

	var createCmd = &cobra.Command{
		Use:   "create",
		Short: "Create a new cluster",
		Run:   runCreate,
	}

	createCmd.Flags().String("config", "", "Path to a kingc.yaml config file")
	createCmd.Flags().String("name", "kingc", "Cluster name")

	var deleteCmd = &cobra.Command{
		Use:   "delete",
		Short: "Tear down a cluster",
		Run:   runDelete,
	}
	deleteCmd.Flags().String("name", "kingc", "Cluster name")

	rootCmd.AddCommand(createCmd)
	rootCmd.AddCommand(deleteCmd)

	if err := rootCmd.Execute(); err != nil {
		klog.Error(err)
		os.Exit(1)
	}
}

func runCreate(cmd *cobra.Command, args []string) {
	configFile, _ := cmd.Flags().GetString("config")
	var cfg *config.Cluster
	var err error

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
	name, _ := cmd.Flags().GetString("name")
	if name != "" {
		cfg.Metadata.Name = name
	}

	if err := cluster.NewManager().Create(cfg); err != nil {
		klog.Fatalf("❌ Error creating cluster: %v", err)
	}
}

func runDelete(cmd *cobra.Command, args []string) {
	name, _ := cmd.Flags().GetString("name")

	if err := cluster.NewManager().Delete(name); err != nil {
		klog.Fatalf("❌ Error deleting cluster: %v", err)
	}
}

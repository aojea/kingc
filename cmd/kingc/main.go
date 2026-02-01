package main

import (
	"flag"
	"os"

	"github.com/aojea/kingc/pkg/cluster"
	"github.com/aojea/kingc/pkg/config"
	"github.com/spf13/cobra"
	"k8s.io/klog/v2"
)

var rootCmd = &cobra.Command{
	Use:   "kingc",
	Short: "Kubernetes IN Google Cloud",
}

func main() {
	klog.InitFlags(nil)
	flag.CommandLine.Set("logtostderr", "true")
	flag.Parse()

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

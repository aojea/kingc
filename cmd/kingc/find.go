package main

import (
	"fmt"
	"strings"
	"sync"

	"github.com/spf13/cobra"
	"k8s.io/klog/v2"
)

var (
	findCmd = &cobra.Command{
		Use:   "find",
		Short: "Find GCP resources",
	}

	findTpuCmd = &cobra.Command{
		Use:   "tpu",
		Short: "Find zones that physically support a GCE TPU model",
		Run:   runFindTpu,
	}

	tpuTypeFlag string
)

func init() {
	rootCmd.AddCommand(findCmd)
	findCmd.AddCommand(findTpuCmd)

	findTpuCmd.Flags().StringVar(&tpuTypeFlag, "type", "v5litepod-8", "TPU accelerator type to search for")
}

func runFindTpu(cmd *cobra.Command, args []string) {
	ctx := cmd.Context()
	client := getClient(cmd)

	klog.Infof("🌍 Querying Google Cloud for global TPU locations...")
	locations, err := client.ListTPULocations(ctx)
	if err != nil {
		klog.Fatalf("❌ Failed to query TPU locations: %v", err)
	}

	klog.Infof("⚡ Verifying which of the %d zones physically support %s (in parallel)...", len(locations), tpuTypeFlag)

	var wg sync.WaitGroup
	var mu sync.Mutex
	var supportedZones []string

	// Prioritize US zones first (highest capacity), then European zones, then others
	var usZones, euroZones, otherZones []string
	for _, loc := range locations {
		if strings.HasPrefix(loc, "us-") {
			usZones = append(usZones, loc)
		} else if strings.HasPrefix(loc, "europe-") {
			euroZones = append(euroZones, loc)
		} else {
			otherZones = append(otherZones, loc)
		}
	}
	orderedZones := append(usZones, append(euroZones, otherZones...)...)

	for _, zone := range orderedZones {
		wg.Add(1)
		go func(z string) {
			defer wg.Done()
			if client.DescribeAcceleratorType(ctx, tpuTypeFlag, z) {
				mu.Lock()
				supportedZones = append(supportedZones, z)
				mu.Unlock()
			}
		}(zone)
	}

	wg.Wait()

	if len(supportedZones) == 0 {
		fmt.Printf("🚨 Accelerator type %q is not supported in any available zones, or you lack permissions.\n", tpuTypeFlag)
		return
	}

	fmt.Println("============================================================")
	fmt.Printf("✅ Found %d zones supporting %s (prioritized by capacity/latency):\n", len(supportedZones), tpuTypeFlag)
	fmt.Println("============================================================")
	for _, z := range orderedZones {
		// Print in order of preference
		for _, sz := range supportedZones {
			if sz == z {
				fmt.Printf(" 🎯 %s\n", sz)
				break
			}
		}
	}
	fmt.Println("============================================================")
}

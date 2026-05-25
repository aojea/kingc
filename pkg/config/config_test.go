package config

import (
	"os"
	"strings"
	"testing"
)

func TestSetDefaults(t *testing.T) {
	tests := []struct {
		name     string
		input    *Cluster
		expected *Cluster
	}{
		{
			name: "Set defaults for empty fields",
			input: &Cluster{
				Spec: Spec{
					Region: "us-west1",
					ControlPlane: NodeGroup{
						Name: "cp",
					},
					WorkerGroups: []NodeGroup{
						{Name: "w1"},
					},
				},
			},
			expected: &Cluster{
				Spec: Spec{
					Region: "us-west1",
					ControlPlane: NodeGroup{
						Name:   "cp",
						Region: "us-west1",
						Zone:   "us-west1-a",
					},
					WorkerGroups: []NodeGroup{
						{
							Name:   "w1",
							Region: "us-west1",
							Zone:   "us-west1-a",
						},
					},
				},
			},
		},
		{
			name: "Respect existing values",
			input: &Cluster{
				Spec: Spec{
					Region: "us-east1",
					ControlPlane: NodeGroup{
						Name:   "cp",
						Region: "us-east1",
						Zone:   "us-east1-b",
					},
					WorkerGroups: []NodeGroup{
						{
							Name:   "w1",
							Region: "europe-west1",
							Zone:   "europe-west1-d",
						},
					},
				},
			},
			expected: &Cluster{
				Spec: Spec{
					Region: "us-east1",
					ControlPlane: NodeGroup{
						Name:   "cp",
						Region: "us-east1",
						Zone:   "us-east1-b",
					},
					WorkerGroups: []NodeGroup{
						{
							Name:   "w1",
							Region: "europe-west1",
							Zone:   "europe-west1-d",
						},
					},
				},
			},
		},
		{
			name: "Derive region from CP zone",
			input: &Cluster{
				Spec: Spec{
					ControlPlane: NodeGroup{
						Zone: "asia-south1-a",
					},
				},
			},
			expected: &Cluster{
				Spec: Spec{
					Region: "asia-south1",
					ControlPlane: NodeGroup{
						Region: "asia-south1",
						Zone:   "asia-south1-a",
					},
				},
			},
		},
		{
			name: "TPU Group Defaults (Zone empty)",
			input: &Cluster{
				Spec: Spec{
					Region: "us-central1",
					TPUGroups: []TPUGroup{
						{
							Name:            "tpu1",
							AcceleratorType: "v5litepod-8",
						},
					},
				},
			},
			expected: &Cluster{
				Spec: Spec{
					Region: "us-central1",
					ControlPlane: NodeGroup{
						Region: "us-central1",
						Zone:   "us-central1-a",
					},
					TPUGroups: []TPUGroup{
						{
							Name:            "tpu1",
							AcceleratorType: "v5litepod-8",
							Zone:            "", // Should remain empty for dynamic zone hunting
							Replicas:        1,
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.input.SetDefaults()

			// Simple checks
			if tt.input.Spec.Region != tt.expected.Spec.Region {
				t.Errorf("expected Region %s, got %s", tt.expected.Spec.Region, tt.input.Spec.Region)
			}
			if tt.input.Spec.ControlPlane.Zone != tt.expected.Spec.ControlPlane.Zone {
				t.Errorf("expected CP Zone %s, got %s", tt.expected.Spec.ControlPlane.Zone, tt.input.Spec.ControlPlane.Zone)
			}
			if len(tt.input.Spec.WorkerGroups) > 0 {
				if tt.input.Spec.WorkerGroups[0].Zone != tt.expected.Spec.WorkerGroups[0].Zone {
					t.Errorf("expected Worker Zone %s, got %s", tt.expected.Spec.WorkerGroups[0].Zone, tt.input.Spec.WorkerGroups[0].Zone)
				}
			}
			if len(tt.input.Spec.TPUGroups) > 0 {
				tgGot := tt.input.Spec.TPUGroups[0]
				tgExp := tt.expected.Spec.TPUGroups[0]
				if tgGot.Zone != tgExp.Zone {
					t.Errorf("expected TPU Zone %q, got %q", tgExp.Zone, tgGot.Zone)
				}
				if tgGot.Replicas != tgExp.Replicas {
					t.Errorf("expected TPU Replicas %d, got %d", tgExp.Replicas, tgGot.Replicas)
				}
				if tgGot.Spot == nil || *tgGot.Spot != true {
					t.Errorf("expected TPU Spot to be true, got %v", tgGot.Spot)
				}
			}
		})
	}
}

func TestValidate(t *testing.T) {

	tests := []struct {
		name    string
		input   *Cluster
		wantErr bool
	}{
		{
			name: "Valid config (Implicit Subnet)",
			input: &Cluster{
				Version: CurrentVersion,
				Spec: Spec{
					Region: "us-central1",
					Networks: []NetworkSpec{{
						Name: "default",
						Subnets: []SubnetSpec{
							{Name: "default", Region: "us-central1", CIDR: "10.0.0.0/24"},
						},
					}},
					ControlPlane: NodeGroup{Region: "us-central1"},
					WorkerGroups: []NodeGroup{{Region: "us-central1"}},
				},
			},
			wantErr: false,
		},
		{
			name: "Missing Subnet in Region",
			input: &Cluster{
				Version: CurrentVersion,
				Spec: Spec{
					Region: "us-central1",
					Networks: []NetworkSpec{{
						Name: "default",
						Subnets: []SubnetSpec{
							{Name: "default", Region: "us-west1", CIDR: "10.0.0.0/24"},
						},
					}},
					ControlPlane: NodeGroup{Region: "us-central1"},
					WorkerGroups: []NodeGroup{{Region: "us-central1"}},
				},
			},
			wantErr: true,
		},
		{
			name: "Cross-region workers with valid subnets",
			input: &Cluster{
				Version: CurrentVersion,
				Spec: Spec{
					Region: "us-central1",
					Networks: []NetworkSpec{{
						Name: "default",
						Subnets: []SubnetSpec{
							{Name: "sub-central", Region: "us-central1", CIDR: "10.0.0.0/24"},
							{Name: "sub-west", Region: "us-west1", CIDR: "10.1.0.0/24"},
						},
					}},
					ControlPlane: NodeGroup{Region: "us-central1"},
					WorkerGroups: []NodeGroup{{Region: "us-west1"}},
				},
			},
			wantErr: false,
		},
		{
			name: "Invalid config (ControlPlane.Replicas > 1)",
			input: &Cluster{
				Version: CurrentVersion,
				Spec: Spec{
					Region: "us-central1",
					Networks: []NetworkSpec{{
						Name: "default",
						Subnets: []SubnetSpec{
							{Name: "sub-central", Region: "us-central1", CIDR: "10.0.0.0/24"},
						},
					}},
					ControlPlane: NodeGroup{Region: "us-central1", Replicas: 3},
					WorkerGroups: []NodeGroup{{Region: "us-central1"}},
				},
			},
			wantErr: true,
		},
		{
			name: "Valid config (ControlPlane.Replicas = 1)",
			input: &Cluster{
				Version: CurrentVersion,
				Spec: Spec{
					Region: "us-central1",
					Networks: []NetworkSpec{{
						Name: "default",
						Subnets: []SubnetSpec{
							{Name: "sub-central", Region: "us-central1", CIDR: "10.0.0.0/24"},
						},
					}},
					ControlPlane: NodeGroup{Region: "us-central1", Replicas: 1},
					WorkerGroups: []NodeGroup{{Region: "us-central1"}},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.input.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoadFromFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "kingc-config-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() {
		if err := os.Remove(tmpFile.Name()); err != nil {
			t.Errorf("Failed to remove temp file: %v", err)
		}
	}()

	content := `
version: v1alpha1
metadata:
  name: should-be-ignored
spec:
  region: us-west2
  controlPlane:
    name: my-cp
`
	if _, err := tmpFile.Write([]byte(content)); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}

	cfg, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}

	// Metadata should be ignored (yaml:"-") and stay as default
	if cfg.Metadata.Name == "should-be-ignored" {
		t.Errorf("Expected metadata.name to be ignored, got 'should-be-ignored'")
	}
	if cfg.Metadata.Name != DefaultClusterName {
		t.Errorf("Expected metadata.name to be default '%s', got '%s'", DefaultClusterName, cfg.Metadata.Name)
	}

	// Spec should be loaded
	if cfg.Spec.Region != "us-west2" {
		t.Errorf("Expected spec.region 'us-west2', got '%s'", cfg.Spec.Region)
	}
	if cfg.Spec.ControlPlane.Name != "my-cp" {
		t.Errorf("Expected cp.name 'my-cp', got '%s'", cfg.Spec.ControlPlane.Name)
	}
}

func TestResolveImage(t *testing.T) {
	tests := []struct {
		name            string
		version         string
		expectedProject string
		expectedImage   string
	}{
		{
			name:            "Prebaked version v1.35.5",
			version:         "v1.35.5",
			expectedProject: "k8s-staging-cluster-api-gcp",
			expectedImage:   "cluster-api-ubuntu-2404-v1-35-5-nightly",
		},
		{
			name:            "Prebaked version without leading v",
			version:         "1.35.0",
			expectedProject: "k8s-staging-cluster-api-gcp",
			expectedImage:   "cluster-api-ubuntu-2404-v1-35-0-nightly",
		},
		{
			name:            "Non-prebaked version fallback",
			version:         "v1.33.0",
			expectedProject: "ubuntu-os-cloud",
			expectedImage:   "ubuntu-2404-lts-amd64",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proj, img := ResolveImage(tt.version)
			if proj != tt.expectedProject {
				t.Errorf("expected project %q, got %q", tt.expectedProject, proj)
			}
			if img != tt.expectedImage {
				t.Errorf("expected image %q, got %q", tt.expectedImage, img)
			}
		})
	}
}

func TestMapTPURuntimeVersion(t *testing.T) {
	tests := []struct {
		tpuType         string
		expectedRuntime string
	}{
		{tpuType: "v6e-4", expectedRuntime: "v2-alpha-tpuv6e"},
		{tpuType: "v5p-8", expectedRuntime: "v2-alpha-tpuv5"},
		{tpuType: "v5litepod-8", expectedRuntime: "v2-alpha-tpuv5-lite"},
		{tpuType: "v4-8", expectedRuntime: "tpu-ubuntu2204-base"},
	}

	for _, tt := range tests {
		got := MapTPURuntimeVersion(tt.tpuType)
		if got != tt.expectedRuntime {
			t.Errorf("MapTPURuntimeVersion(%q) = %q, expected %q", tt.tpuType, got, tt.expectedRuntime)
		}
	}
}

func TestDeriveSubnetCIDR(t *testing.T) {
	c1 := deriveSubnetCIDR("us-central1")
	c2 := deriveSubnetCIDR("us-east5")
	c3 := deriveSubnetCIDR("europe-west4")

	if c1 == c2 || c1 == c3 || c2 == c3 {
		t.Errorf("expected unique derived CIDRs, got: central=%s, east=%s, europe=%s", c1, c2, c3)
	}
	
	// Check pattern format
	if !strings.HasPrefix(c1, "10.") || !strings.HasSuffix(c1, ".0.0/24") {
		t.Errorf("expected format 10.X.0.0/24, got %q", c1)
	}
}

func TestTPUHelpers(t *testing.T) {
	countTests := []struct {
		tpuType  string
		expected string
	}{
		{"v5litepod-8", "8"},
		{"v5litepod-4", "4"},
		{"v6e-4", "4"},
		{"v5p-8", "8"},
		{"v4", "4"}, // Fallback default
	}

	for _, tt := range countTests {
		got := GetTPUChipCount(tt.tpuType)
		if got != tt.expected {
			t.Errorf("GetTPUChipCount(%q) = %q, expected %q", tt.tpuType, got, tt.expected)
		}
	}

	topoTests := []struct {
		tpuType  string
		expected string
	}{
		{"v5litepod-1", "1x1"},
		{"v5litepod-4", "2x2"},
		{"v5litepod-8", "2x4"},
		{"v5litepod-16", "4x4"},
		{"v5litepod-32", "4x8"},
		{"v5litepod-64", "8x8"},
		{"v5litepod-128", "8x16"},
		{"v5litepod-256", "16x16"},
		{"invalid", "2x2"},
	}

	for _, tt := range topoTests {
		got := GetTPUTopology(tt.tpuType)
		if got != tt.expected {
			t.Errorf("GetTPUTopology(%q) = %q, expected %q", tt.tpuType, got, tt.expected)
		}
	}
}





package config

import (
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.input.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

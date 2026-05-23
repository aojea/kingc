package config

import (
	"strings"
)

var prebakedImages = map[string]string{
	"v1.34.3": "cluster-api-ubuntu-2404-v1-34-3-nightly",
	"v1.34.8": "cluster-api-ubuntu-2404-v1-34-8-nightly",
	"v1.35.0": "cluster-api-ubuntu-2404-v1-35-0-nightly",
	"v1.35.5": "cluster-api-ubuntu-2404-v1-35-5-nightly",
}

// ResolveImage returns the image project and image name for a given Kubernetes version.
// If the version is not prebaked, it falls back to the standard Ubuntu 24.04 LTS image.
func ResolveImage(version string) (string, string) {
	// Normalize version to have a leading 'v'
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}

	if imageName, ok := prebakedImages[version]; ok {
		return "k8s-staging-cluster-api-gcp", imageName
	}

	// Fallback to original Ubuntu 24.04 LTS image
	return "ubuntu-os-cloud", "ubuntu-2404-lts-amd64"
}

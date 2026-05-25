package config

import "strings"

// MapTPURuntimeVersion dynamically maps the requested TPU model to the required TPU software version.
func MapTPURuntimeVersion(tpuType string) string {
	switch {
	case strings.HasPrefix(tpuType, "v6e"):
		return "v2-alpha-tpuv6e"
	case strings.HasPrefix(tpuType, "v5p"):
		return "v2-alpha-tpuv5"
	case strings.HasPrefix(tpuType, "v5litepod"):
		return "v2-alpha-tpuv5-lite"
	default:
		return "tpu-ubuntu2204-base" // v4 and older
	}
}

// MapTPUAcceleratorLabel dynamically maps GCE TPU model names to GKE's standard accelerator label values.
func MapTPUAcceleratorLabel(tpuType string) string {
	if strings.HasPrefix(tpuType, "v5litepod-") {
		return "tpu-v5-lite-podslice"
	}
	return tpuType
}

// GetTPUChipCount extracts the chip count from the TPU type string.
func GetTPUChipCount(tpuType string) string {
	parts := strings.Split(tpuType, "-")
	if len(parts) == 2 {
		return parts[1]
	}
	// Default to 4 if not specified or unable to parse
	return "4"
}

// GetTPUTopology returns the default topology for a given TPU type and chip count.
func GetTPUTopology(tpuType string) string {
	parts := strings.Split(tpuType, "-")
	if len(parts) != 2 {
		return "2x2" // default fallback
	}
	count := parts[1]
	switch count {
	case "1":
		return "1x1"
	case "4":
		return "2x2"
	case "8":
		return "2x4"
	case "16":
		return "4x4"
	case "32":
		return "4x8"
	case "64":
		return "8x8"
	case "128":
		return "8x16"
	case "256":
		return "16x16"
	default:
		return "2x2"
	}
}


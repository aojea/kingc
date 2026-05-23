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

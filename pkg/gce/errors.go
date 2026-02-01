package gce

import "strings"

func IsAlreadyExistsError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "already exists")
}

func IsNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "NotFound")
}

func IsPermissionDeniedError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "permission denied") || strings.Contains(err.Error(), "PermissionDenied")
}

func IsQuotaExceededError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "quota exceeded") || strings.Contains(err.Error(), "QuotaExceeded")
}

func IsRateLimitError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "rate limit exceeded") || strings.Contains(err.Error(), "RateLimitExceeded")
}

func IsTransientError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "transient error") || strings.Contains(err.Error(), "TransientError")
}

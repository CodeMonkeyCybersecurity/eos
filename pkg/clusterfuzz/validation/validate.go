// Package validation provides validation utilities for ClusterFuzz configuration
package validation

import (
	"fmt"
)

// ValidateConfig validates the ClusterFuzz configuration.
// It follows the Assess → Intervene → Evaluate pattern.
func ValidateConfig(storageBackend, databaseBackend, queueBackend string, botCount, preemptibleBotCount int, s3Endpoint, s3AccessKey, s3SecretKey string) error {
	// ASSESS - Check basic validation requirements
	// Validate storage backend
	validStorage := []string{"minio", "s3", "local"}
	if !containsString(validStorage, storageBackend) {
		return fmt.Errorf("invalid storage backend: %s (valid: %v)", storageBackend, validStorage)
	}

	// Validate database backend
	validDB := []string{"postgresql", "mongodb"}
	if !containsString(validDB, databaseBackend) {
		return fmt.Errorf("invalid database backend: %s (valid: %v)", databaseBackend, validDB)
	}

	// Validate queue backend
	validQueue := []string{"redis", "rabbitmq"}
	if !containsString(validQueue, queueBackend) {
		return fmt.Errorf("invalid queue backend: %s (valid: %v)", queueBackend, validQueue)
	}

	// INTERVENE - Validate specific backend configurations
	// Validate S3 configuration if using S3/MinIO
	if storageBackend == "s3" || storageBackend == "minio" {
		if s3Endpoint == "" && storageBackend == "minio" {
			// Default MinIO endpoint will be set later
		}
		if s3AccessKey == "" || s3SecretKey == "" {
			return fmt.Errorf("S3 access key and secret key are required for %s backend", storageBackend)
		}
	}

	// EVALUATE - Validate bot counts
	if botCount < 0 || preemptibleBotCount < 0 {
		return fmt.Errorf("bot counts must be non-negative")
	}

	return nil
}

// containsString checks if a string slice contains a specific string
func containsString(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

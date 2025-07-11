// Package config provides configuration creation utilities for ClusterFuzz
package config

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/clusterfuzz"
)

// CreateConfig creates a new ClusterFuzz configuration.
// It follows the Assess → Intervene → Evaluate pattern.
func CreateConfig(nomadAddress, consulAddress, storageBackend, databaseBackend, queueBackend string,
	botCount, preemptibleBotCount int, domain, configDir string, useVault bool, vaultPath string,
	s3Endpoint, s3AccessKey, s3SecretKey, s3Bucket string) *clusterfuzz.Config {
	
	// ASSESS - Initialize base configuration
	config := &clusterfuzz.Config{
		NomadAddress:        nomadAddress,
		ConsulAddress:       consulAddress,
		StorageBackend:      storageBackend,
		DatabaseBackend:     databaseBackend,
		QueueBackend:        queueBackend,
		BotCount:            botCount,
		PreemptibleBotCount: preemptibleBotCount,
		Domain:              domain,
		ConfigDir:           configDir,
		UseVault:            useVault,
		VaultPath:           vaultPath,
		Timestamp:           time.Now().Format("20060102-150405"),
	}

	// INTERVENE - Configure storage backend
	if storageBackend == "s3" || storageBackend == "minio" {
		config.S3Config = clusterfuzz.S3Config{
			Endpoint:  s3Endpoint,
			AccessKey: s3AccessKey,
			SecretKey: s3SecretKey,
			Bucket:    s3Bucket,
			UseSSL:    !strings.HasPrefix(s3Endpoint, "http://"),
		}
		// Set default MinIO endpoint if needed
		if config.S3Config.Endpoint == "" && storageBackend == "minio" {
			config.S3Config.Endpoint = "http://localhost:9000"
		}
	}

	// Configure database
	switch databaseBackend {
	case "postgresql":
		config.DatabaseConfig = clusterfuzz.DatabaseConfig{
			Type:     "postgresql",
			Host:     "clusterfuzz-postgres.service.consul",
			Port:     5432,
			Database: "clusterfuzz",
			Username: "clusterfuzz",
			Password: generatePassword(),
		}
	case "mongodb":
		config.DatabaseConfig = clusterfuzz.DatabaseConfig{
			Type:     "mongodb",
			Host:     "clusterfuzz-mongodb.service.consul",
			Port:     27017,
			Database: "clusterfuzz",
			Username: "clusterfuzz",
			Password: generatePassword(),
		}
	}

	// EVALUATE - Configure queue
	switch queueBackend {
	case "redis":
		config.QueueConfig = clusterfuzz.QueueConfig{
			Type:     "redis",
			Host:     "clusterfuzz-redis.service.consul",
			Port:     6379,
			Password: generatePassword(),
		}
	case "rabbitmq":
		config.QueueConfig = clusterfuzz.QueueConfig{
			Type:     "rabbitmq",
			Host:     "clusterfuzz-rabbitmq.service.consul",
			Port:     5672,
			Username: "clusterfuzz",
			Password: generatePassword(),
		}
	}

	return config
}

// generatePassword generates a secure random password
func generatePassword() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based password
		return "cf_" + time.Now().Format("20060102150405")
	}
	return hex.EncodeToString(bytes)
}
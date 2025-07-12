// Package clusterfuzz provides types and utilities for ClusterFuzz deployment
package clusterfuzz

// Config holds the complete ClusterFuzz configuration
type Config struct {
	NomadAddress        string
	ConsulAddress       string
	StorageBackend      string
	DatabaseBackend     string
	QueueBackend        string
	BotCount            int
	PreemptibleBotCount int
	Domain              string
	ConfigDir           string
	UseVault            bool
	VaultPath           string
	S3Config            S3Config
	DatabaseConfig      DatabaseConfig
	QueueConfig         QueueConfig
	Timestamp           string
}

// S3Config holds S3/MinIO configuration
type S3Config struct {
	Endpoint  string
	AccessKey string
	SecretKey string
	Bucket    string
	UseSSL    bool
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Type     string
	Host     string
	Port     int
	Database string
	Username string
	Password string
}

// QueueConfig holds queue configuration
type QueueConfig struct {
	Type     string
	Host     string
	Port     int
	Username string
	Password string
}

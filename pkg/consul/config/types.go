package config

// ConsulConfig holds configuration options for Consul
type ConsulConfig struct {
	DatacenterName     string
	EnableDebugLogging bool
	VaultAvailable     bool
}

package config

// ConsulConfig holds configuration options for Consul
type ConsulConfig struct {
	DatacenterName     string
	EnableDebugLogging bool
	VaultAvailable     bool
	BootstrapExpect    int  // Number of expected servers (1 = use bootstrap mode, >1 = use bootstrap_expect)
}

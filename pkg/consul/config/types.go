package config

// GeneratorConfig holds configuration options for Consul config file generation
// Renamed from ConsulConfig to avoid confusion with consul.ConsulConfig (main type)
// This is specifically for the config generator, not the full Consul configuration
type GeneratorConfig struct {
	DatacenterName     string
	EnableDebugLogging bool
	VaultAvailable     bool
	BootstrapExpect    int // Number of expected servers (1 = use bootstrap mode, >1 = use bootstrap_expect)
}

// DEPRECATED: ConsulConfig is renamed to GeneratorConfig for clarity
// Use GeneratorConfig instead. This alias maintained for backwards compatibility.
type ConsulConfig = GeneratorConfig

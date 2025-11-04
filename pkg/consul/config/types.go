package config

// GeneratorConfig holds configuration options for Consul config file generation
// Renamed from ConsulConfig to avoid confusion with consul.ConsulConfig (main type)
// This is specifically for the config generator, not the full Consul configuration
type GeneratorConfig struct {
	DatacenterName     string
	EnableDebugLogging bool
	VaultAvailable     bool
	BootstrapExpect    int // Number of expected servers (1 = use bootstrap mode, >1 = use bootstrap_expect)
	ClientAddr         string
	GossipKey          string
	// EnableLocalScriptChecks explicitly re-enables local script checks.
	// Default is false to align with HashiCorp guidance (script checks disabled).
	EnableLocalScriptChecks bool
	// EnableVaultWatcher adds the consul-vault-helper script watcher.
	// Disabled by default because it relies on script handlers.
	EnableVaultWatcher bool
}

// DEPRECATED: ConsulConfig is renamed to GeneratorConfig for clarity
// Use GeneratorConfig instead. This alias maintained for backwards compatibility.
type ConsulConfig = GeneratorConfig

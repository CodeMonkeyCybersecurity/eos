package bootstrap

// SaltConfig holds configuration for Salt bootstrap
type SaltConfig struct {
	MasterMode    bool   // Install as master-minion instead of masterless
	MasterAddress string // Salt master address for minion mode
	Version       string // Salt version to install
}

// VaultConfig holds configuration for Vault bootstrap
type VaultConfig struct {
	Version     string // Vault version to install
	StorageType string // Storage backend type (file, consul, etc)
	ListenAddr  string // API listen address
}

// OSQueryConfig holds configuration for OSQuery bootstrap
type OSQueryConfig struct {
	Version string // OSQuery version to install
}
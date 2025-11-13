// pkg/consul/cli_vars.go

package consul

// CLI flag variables for Consul installation
// These are exported so cmd/create/consul.go can bind them to cobra flags
var (
	ConsulDatacenter string
	ConsulBindAddr   string
	ConsulServer     bool
	ConsulClient     bool
	ConsulNoVault    bool
	ConsulDebug      bool
	ConsulForce      bool
	ConsulClean      bool
	ConsulBinary     bool
	ConsulVersion    string
)

// pkg/temporal/types.go
package temporal

const (
	// TemporalVersion is the version of Temporal to install
	TemporalVersion = "1.24.2"

	// PostgreSQLVersion is the PostgreSQL version for persistence
	PostgreSQLVersion = "15"

	// InstallDir is where Temporal configuration is stored
	InstallDir = "/opt/temporal-iris"

	// DataDir is where Temporal data is stored
	DataDir = "/var/lib/temporal-iris"

	// ServiceName is the systemd service name
	ServiceName = "temporal-iris"

	// Default configuration
	DefaultHost              = "0.0.0.0"
	DefaultPort              = 7233
	DefaultUIPort            = 8233
	DefaultMetricsPort       = 9090
	DefaultHistoryShards     = 4
	DefaultWorkflowRetention = "168h" // 7 days
)

// TemporalConfig holds configuration for Temporal installation
type TemporalConfig struct {
	Version            string
	PostgreSQLVersion  string
	InstallDir         string
	DataDir            string
	Host               string
	Port               int
	UIPort             int
	MetricsPort        int
	HistoryShards      int
	WorkflowRetention  string
	PostgreSQLPassword string
	EnableMetrics      bool
	EnableArchival     bool
}

// DefaultConfig returns default Temporal configuration
func DefaultConfig() *TemporalConfig {
	return &TemporalConfig{
		Version:           TemporalVersion,
		PostgreSQLVersion: PostgreSQLVersion,
		InstallDir:        InstallDir,
		DataDir:           DataDir,
		Host:              DefaultHost,
		Port:              DefaultPort,
		UIPort:            DefaultUIPort,
		MetricsPort:       DefaultMetricsPort,
		HistoryShards:     DefaultHistoryShards,
		WorkflowRetention: DefaultWorkflowRetention,
		EnableMetrics:     true,
		EnableArchival:    false,
	}
}

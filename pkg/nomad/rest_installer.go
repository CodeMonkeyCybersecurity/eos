// pkg/nomad/rest_installer.go

package nomad

import (
	"context"
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RESTInstaller handles Nomad installation via Salt REST API
type RESTInstaller struct {
	restClient *saltstack.RESTClient
	logger     *zap.Logger
}

// NewRESTInstaller creates a new REST-based installer
func NewRESTInstaller(apiURL string, skipTLSVerify bool) *RESTInstaller {
	return &RESTInstaller{
		restClient: saltstack.NewRESTClient(apiURL, skipTLSVerify),
		logger:     zap.L(),
	}
}

// Authenticate authenticates with the Salt API
func (i *RESTInstaller) Authenticate(ctx context.Context, username, password string) error {
	return i.restClient.Authenticate(ctx, username, password, "pam")
}

// InstallNomad installs Nomad using Salt REST API
func (i *RESTInstaller) InstallNomad(rc *eos_io.RuntimeContext, config *NomadInstallConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing Nomad via Salt REST API")

	// Prepare pillar data
	pillarData := map[string]interface{}{
		"nomad": map[string]interface{}{
			"ensure":            "present",
			"server_mode":       config.ServerMode,
			"client_mode":       config.ClientMode,
			"bootstrap_expect":  config.BootstrapExpect,
			"datacenter":        config.Datacenter,
			"region":            config.Region,
			"bind_addr":         config.BindAddr,
			"advertise_addr":    config.AdvertiseAddr,
			"log_level":         config.LogLevel,
			"enable_acl":        config.EnableACL,
			"force":             config.Force,
			"clean":             config.Clean,
			"join_addrs":        config.JoinAddrs,
			"client_servers":    config.ClientServers,
			"enable_docker":     config.EnableDocker,
			"enable_raw_exec":   config.EnableRawExec,
			"consul_integration": config.ConsulIntegration,
			"vault_integration": config.VaultIntegration,
		},
	}

	// Apply the Nomad installation state
	logger.Info("Applying Nomad installation state")
	result, err := i.restClient.ApplyState(rc.Ctx, "*", "hashicorp.nomad", pillarData)
	if err != nil {
		return fmt.Errorf("failed to apply Nomad state: %w", err)
	}

	// Check results
	logger.Info("Checking installation results")
	successCount := 0
	failureCount := 0
	
	for minion, minionResult := range result {
		if isStateSuccessful(minionResult) {
			successCount++
			logger.Info("Nomad installed successfully on minion", zap.String("minion", minion))
		} else {
			failureCount++
			logger.Error("Nomad installation failed on minion", 
				zap.String("minion", minion),
				zap.Any("result", minionResult))
		}
	}

	if failureCount > 0 {
		return fmt.Errorf("Nomad installation failed on %d minion(s)", failureCount)
	}

	logger.Info("Nomad installation completed successfully", 
		zap.Int("successful_minions", successCount))
	return nil
}

// RemoveNomad removes Nomad using Salt REST API
func (i *RESTInstaller) RemoveNomad(rc *eos_io.RuntimeContext, config *NomadRemoveConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Removing Nomad via Salt REST API")

	// Prepare pillar data for removal
	pillarData := map[string]interface{}{
		"nomad": map[string]interface{}{
			"ensure":      "absent",
			"force":       config.Force,
			"keep_data":   config.KeepData,
			"keep_config": config.KeepConfig,
			"keep_user":   config.KeepUser,
			"timeout":     config.Timeout,
			"server_mode": config.ServerMode,
			"client_mode": config.ClientMode,
			"node_id":     config.NodeID,
		},
	}

	// Apply the Nomad removal state
	logger.Info("Applying Nomad removal state")
	result, err := i.restClient.ApplyState(rc.Ctx, "*", "hashicorp.nomad_remove", pillarData)
	if err != nil {
		return fmt.Errorf("failed to apply Nomad removal state: %w", err)
	}

	// Check results
	logger.Info("Checking removal results")
	successCount := 0
	failureCount := 0
	
	for minion, minionResult := range result {
		if isStateSuccessful(minionResult) {
			successCount++
			logger.Info("Nomad removed successfully from minion", zap.String("minion", minion))
		} else {
			failureCount++
			logger.Error("Nomad removal failed on minion", 
				zap.String("minion", minion),
				zap.Any("result", minionResult))
		}
	}

	if failureCount > 0 {
		return fmt.Errorf("Nomad removal failed on %d minion(s)", failureCount)
	}

	logger.Info("Nomad removal completed successfully", 
		zap.Int("successful_minions", successCount))
	return nil
}

// CheckNomadStatus checks Nomad status across minions
func (i *RESTInstaller) CheckNomadStatus(rc *eos_io.RuntimeContext) (map[string]NomadRESTStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking Nomad status via Salt REST API")

	// Execute status check command
	result, err := i.restClient.ExecuteCommand(rc.Ctx, "*", "cmd.run", 
		[]interface{}{"nomad status 2>&1 || echo 'NOT_INSTALLED'"}, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to check Nomad status: %w", err)
	}

	// Parse results
	statusMap := make(map[string]NomadRESTStatus)
	for minion, output := range result {
		status := parseNomadStatus(output)
		statusMap[minion] = status
		
		logger.Debug("Nomad status on minion",
			zap.String("minion", minion),
			zap.Bool("installed", status.Installed),
			zap.Bool("running", status.Running))
	}

	return statusMap, nil
}

// TestConnection tests the connection to Salt API
func (i *RESTInstaller) TestConnection(ctx context.Context) error {
	return i.restClient.ValidateConnection(ctx)
}

// Helper function to check if a state execution was successful
func isStateSuccessful(result interface{}) bool {
	// Salt state results are complex nested structures
	// This is a simplified check - in production you'd want more thorough parsing
	resultMap, ok := result.(map[string]interface{})
	if !ok {
		return false
	}

	// Check for any failed states
	for _, stateResult := range resultMap {
		if stateMap, ok := stateResult.(map[string]interface{}); ok {
			if result, exists := stateMap["result"]; exists {
				if success, ok := result.(bool); ok && !success {
					return false
				}
			}
		}
	}

	return true
}

// Helper function to parse Nomad status from command output
func parseNomadStatus(output interface{}) NomadRESTStatus {
	status := NomadRESTStatus{}
	
	outputStr, ok := output.(string)
	if !ok {
		return status
	}

	// Check if Nomad is installed
	if outputStr == "NOT_INSTALLED" || strings.Contains(outputStr, "command not found") {
		status.Installed = false
		return status
	}

	status.Installed = true
	
	// Parse additional status information
	if strings.Contains(outputStr, "Nomad agent is running") {
		status.Running = true
	}
	
	// Extract version if available
	if strings.Contains(outputStr, "Nomad v") {
		// Simple version extraction - could be improved
		parts := strings.Split(outputStr, "Nomad v")
		if len(parts) > 1 {
			versionParts := strings.Fields(parts[1])
			if len(versionParts) > 0 {
				status.Version = versionParts[0]
			}
		}
	}

	return status
}

// NomadInstallConfig represents Nomad installation configuration for REST API
type NomadInstallConfig struct {
	ServerMode        bool
	ClientMode        bool
	BootstrapExpect   int
	Datacenter        string
	Region            string
	BindAddr          string
	AdvertiseAddr     string
	LogLevel          string
	EnableACL         bool
	Force             bool
	Clean             bool
	JoinAddrs         []string
	ClientServers     []string
	EnableDocker      bool
	EnableRawExec     bool
	ConsulIntegration bool
	VaultIntegration  bool
}

// NomadRemoveConfig represents Nomad removal configuration
type NomadRemoveConfig struct {
	Force      bool
	KeepData   bool
	KeepConfig bool
	KeepUser   bool
	Timeout    int
	ServerMode bool
	ClientMode bool
	NodeID     string
}

// NomadRESTStatus represents the status of a Nomad installation from REST API
type NomadRESTStatus struct {
	Installed bool
	Running   bool
	Version   string
	Failed    bool
}
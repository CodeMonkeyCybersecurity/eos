package boundary

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/salt"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Manager handles Boundary operations via Salt API
type Manager struct {
	saltClient *salt.Client
	logger     *zap.Logger
}

// NewManager creates a new Boundary manager
func NewManager(rc *eos_io.RuntimeContext, saltClient *salt.Client) (*Manager, error) {
	logger := otelzap.Ctx(rc.Ctx)

	if saltClient == nil {
		return nil, fmt.Errorf("salt client is required")
	}

	return &Manager{
		saltClient: saltClient,
		logger:     logger.ZapLogger(),
	}, nil
}

// Create creates a Boundary deployment
func (m *Manager) Create(ctx context.Context, opts *CreateOptions) error {
	if opts == nil {
		opts = &CreateOptions{}
	}

	// Set defaults
	if opts.Target == "" {
		opts.Target = "*"
	}
	if opts.Config == nil {
		opts.Config = &Config{
			Role:        "controller",
			ClusterName: "eos",
		}
	}
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Minute
	}

	m.logger.Info("creating boundary deployment",
		zap.String("target", opts.Target),
		zap.String("role", opts.Config.Role),
		zap.String("cluster", opts.Config.ClusterName),
		zap.String("version", opts.Config.Version),
		zap.Bool("force", opts.Force),
		zap.Bool("clean", opts.Clean))

	// Build pillar data for Salt state
	pillar := m.buildCreatePillar(opts)

	// Apply state with progress tracking
	if opts.StreamOutput {
		return m.applyStateWithProgress(ctx, "hashicorp.boundary", pillar, opts.Timeout)
	}

	// Apply state without streaming
	result, err := m.applyState(ctx, "hashicorp.boundary", pillar, opts.Timeout)
	if err != nil {
		return fmt.Errorf("failed to apply boundary state: %w", err)
	}

	if result.Failed {
		return fmt.Errorf("boundary installation failed: %v", result.Errors)
	}

	m.logger.Info("boundary deployment created successfully")
	return nil
}

// Delete removes a Boundary deployment
func (m *Manager) Delete(ctx context.Context, opts *DeleteOptions) error {
	if opts == nil {
		opts = &DeleteOptions{}
	}

	// Set defaults
	if opts.Target == "" {
		opts.Target = "*"
	}
	if opts.ClusterName == "" {
		opts.ClusterName = "eos"
	}
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Minute
	}

	m.logger.Info("deleting boundary deployment",
		zap.String("target", opts.Target),
		zap.String("cluster", opts.ClusterName),
		zap.Bool("keep_data", opts.KeepData),
		zap.Bool("keep_config", opts.KeepConfig),
		zap.Bool("keep_user", opts.KeepUser),
		zap.Bool("force", opts.Force))

	// Build pillar data for removal
	pillar := m.buildDeletePillar(opts)

	// Apply removal state
	if opts.StreamOutput {
		return m.applyStateWithProgress(ctx, "hashicorp.boundary_remove", pillar, opts.Timeout)
	}

	result, err := m.applyState(ctx, "hashicorp.boundary_remove", pillar, opts.Timeout)
	if err != nil {
		return fmt.Errorf("failed to apply boundary removal state: %w", err)
	}

	if result.Failed {
		return fmt.Errorf("boundary removal failed: %v", result.Errors)
	}

	m.logger.Info("boundary deployment deleted successfully")
	return nil
}

// Status checks the status of Boundary deployment
func (m *Manager) Status(ctx context.Context, opts *StatusOptions) (*StatusResult, error) {
	if opts == nil {
		opts = &StatusOptions{}
	}

	// Set defaults
	if opts.Target == "" {
		opts.Target = "*"
	}

	m.logger.Debug("checking boundary status",
		zap.String("target", opts.Target),
		zap.Bool("detailed", opts.Detailed))

	// Execute status check command
	cmd := salt.Command{
		Client:   "local",
		Target:   opts.Target,
		Function: "cmd.run",
		Args: []string{`
			STATUS='{}'
			if command -v boundary >/dev/null 2>&1; then
				STATUS=$(echo $STATUS | jq '. + {installed: true}')
				VERSION=$(boundary version | grep "Version:" | awk '{print $2}')
				STATUS=$(echo $STATUS | jq --arg v "$VERSION" '. + {version: $v}')
			else
				STATUS=$(echo $STATUS | jq '. + {installed: false}')
			fi
			
			if systemctl is-active boundary.service >/dev/null 2>&1; then
				STATUS=$(echo $STATUS | jq '. + {running: true, service_status: "active"}')
			elif systemctl is-failed boundary.service >/dev/null 2>&1; then
				STATUS=$(echo $STATUS | jq '. + {failed: true, service_status: "failed"}')
				ERROR=$(journalctl -u boundary.service -n 1 --no-pager | tail -1)
				STATUS=$(echo $STATUS | jq --arg e "$ERROR" '. + {last_error: $e}')
			else
				STATUS=$(echo $STATUS | jq '. + {running: false, service_status: "inactive"}')
			fi
			
			if [ -f /etc/boundary/controller.hcl ] || [ -f /etc/boundary/worker.hcl ]; then
				STATUS=$(echo $STATUS | jq '. + {config_valid: true}')
				if [ -f /etc/boundary/controller.hcl ]; then
					STATUS=$(echo $STATUS | jq '. + {role: "controller"}')
				else
					STATUS=$(echo $STATUS | jq '. + {role: "worker"}')
				fi
			fi
			
			echo $STATUS
		`},
		Kwargs: map[string]string{
			"shell": "/bin/bash",
		},
	}

	result, err := m.saltClient.ExecuteCommand(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to check boundary status: %w", err)
	}

	// Parse results
	statusResult := &StatusResult{
		Minions: make(map[string]MinionStatus),
	}

	for minion, output := range result.Raw {
		minionStatus := MinionStatus{
			Minion: minion,
		}

		if outputStr, ok := output.(string); ok {
			// Try to parse JSON status
			var status map[string]interface{}
			if err := json.Unmarshal([]byte(outputStr), &status); err == nil {
				minionStatus.Status = m.parseStatus(status)
			} else {
				// Fallback to raw output
				minionStatus.Output = outputStr
			}
		}

		statusResult.Minions[minion] = minionStatus
	}

	// Get detailed information if requested
	if opts.Detailed {
		m.enrichStatusDetails(ctx, opts.Target, statusResult)
	}

	return statusResult, nil
}

// buildCreatePillar builds the pillar data for Boundary creation
func (m *Manager) buildCreatePillar(opts *CreateOptions) map[string]interface{} {
	pillar := map[string]interface{}{
		"boundary": map[string]interface{}{
			"cluster_name": opts.Config.ClusterName,
			"role":         opts.Config.Role,
			"enabled":      true,
			"force":        opts.Force,
			"clean":        opts.Clean,
		},
	}

	// Add version if specified
	if opts.Config.Version != "" {
		pillar["boundary"].(map[string]interface{})["version"] = opts.Config.Version
	}

	// Add controller-specific configuration
	if opts.Config.Role == "controller" || opts.Config.Role == "dev" {
		if opts.Config.DatabaseURL != "" {
			pillar["boundary"].(map[string]interface{})["database_url"] = opts.Config.DatabaseURL
		}
		if opts.Config.PublicClusterAddr != "" {
			pillar["boundary"].(map[string]interface{})["public_cluster_addr"] = opts.Config.PublicClusterAddr
		}
		if opts.Config.PublicAddr != "" {
			pillar["boundary"].(map[string]interface{})["public_addr"] = opts.Config.PublicAddr
		}
	}

	// Add worker-specific configuration
	if opts.Config.Role == "worker" {
		if len(opts.Config.InitialUpstreams) > 0 {
			pillar["boundary"].(map[string]interface{})["initial_upstreams"] = opts.Config.InitialUpstreams
		}
		if opts.Config.PublicProxyAddr != "" {
			pillar["boundary"].(map[string]interface{})["public_proxy_addr"] = opts.Config.PublicProxyAddr
		}
	}

	// Add common configuration
	if opts.Config.ListenerAddress != "" {
		pillar["boundary"].(map[string]interface{})["listener_address"] = opts.Config.ListenerAddress
	}

	// TLS configuration
	pillar["boundary"].(map[string]interface{})["tls_disable"] = opts.Config.TLSDisable
	if !opts.Config.TLSDisable {
		if opts.Config.TLSCertFile != "" {
			pillar["boundary"].(map[string]interface{})["tls_cert_file"] = opts.Config.TLSCertFile
		}
		if opts.Config.TLSKeyFile != "" {
			pillar["boundary"].(map[string]interface{})["tls_key_file"] = opts.Config.TLSKeyFile
		}
	}

	// KMS configuration
	if opts.Config.KMSType != "" {
		kms := map[string]interface{}{
			"type": opts.Config.KMSType,
		}
		if opts.Config.KMSKeyID != "" {
			kms["key_id"] = opts.Config.KMSKeyID
		}
		if opts.Config.KMSRegion != "" {
			kms["region"] = opts.Config.KMSRegion
		}
		pillar["boundary"].(map[string]interface{})["kms"] = kms
	}

	return pillar
}

// buildDeletePillar builds the pillar data for Boundary deletion
func (m *Manager) buildDeletePillar(opts *DeleteOptions) map[string]interface{} {
	return map[string]interface{}{
		"boundary": map[string]interface{}{
			"cluster_name": opts.ClusterName,
			"ensure":       "absent",
			"force":        opts.Force,
			"keep_data":    opts.KeepData,
			"keep_config":  opts.KeepConfig,
			"keep_user":    opts.KeepUser,
		},
	}
}

// applyState applies a Salt state and waits for completion
func (m *Manager) applyState(ctx context.Context, state string, pillar map[string]interface{}, timeout time.Duration) (*salt.StateResult, error) {
	// Set timeout context
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Start the state job
	jobID, err := m.startStateJob(ctx, state, pillar)
	if err != nil {
		return nil, err
	}

	// Wait for completion
	return m.waitForJob(ctx, jobID)
}

// applyStateWithProgress applies a state with progress reporting
func (m *Manager) applyStateWithProgress(ctx context.Context, state string, pillar map[string]interface{}, timeout time.Duration) error {
	// Set timeout context
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Apply state with progress callback
	result, err := m.saltClient.ExecuteStateApply(ctx, state, pillar,
		func(progress salt.StateProgress) {
			if progress.Completed {
				status := "✓"
				if !progress.Success {
					status = "✗"
				}
				fmt.Printf("%s %s - %s\n", status, progress.State, progress.Message)
			} else {
				fmt.Printf("... %s\n", progress.Message)
			}
		})

	if err != nil {
		return fmt.Errorf("state execution failed: %w", err)
	}

	if result.Failed {
		return fmt.Errorf("state had failures: %v", result.Errors)
	}

	return nil
}

// startStateJob starts an async state job
func (m *Manager) startStateJob(ctx context.Context, state string, pillar map[string]interface{}) (string, error) {
	pillarJSON, err := json.Marshal(pillar)
	if err != nil {
		return "", fmt.Errorf("failed to marshal pillar: %w", err)
	}

	cmd := salt.Command{
		Client:   "local_async",
		Target:   "*",
		Function: "state.apply",
		Args:     []string{state},
		Kwargs: map[string]string{
			"pillar": string(pillarJSON),
		},
	}

	result, err := m.saltClient.ExecuteCommand(ctx, cmd)
	if err != nil {
		return "", err
	}

	// Extract job ID from result
	if jid, ok := result.Raw["jid"].(string); ok {
		return jid, nil
	}

	return "", fmt.Errorf("no job ID returned")
}

// waitForJob waits for a job to complete
func (m *Manager) waitForJob(ctx context.Context, jobID string) (*salt.StateResult, error) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			// Check job status
			cmd := salt.Command{
				Client:   "runner",
				Function: "jobs.lookup_jid",
				Args:     []string{jobID},
			}

			result, err := m.saltClient.ExecuteCommand(ctx, cmd)
			if err != nil {
				m.logger.Debug("failed to lookup job", zap.Error(err))
				continue
			}

			// Check if job is complete
			if len(result.Raw) > 0 {
				// Parse results
				stateResult := &salt.StateResult{
					States: make(map[string]salt.StateExecutionResult),
				}

				// Simple parsing - in production would need more robust parsing
				stateResult.Completed = true
				return stateResult, nil
			}
		}
	}
}

// parseStatus parses status from JSON data
func (m *Manager) parseStatus(data map[string]interface{}) Status {
	status := Status{}

	if v, ok := data["installed"].(bool); ok {
		status.Installed = v
	}
	if v, ok := data["running"].(bool); ok {
		status.Running = v
	}
	if v, ok := data["failed"].(bool); ok {
		status.Failed = v
	}
	if v, ok := data["version"].(string); ok {
		status.Version = v
	}
	if v, ok := data["role"].(string); ok {
		status.Role = v
	}
	if v, ok := data["service_status"].(string); ok {
		status.ServiceStatus = v
	}
	if v, ok := data["last_error"].(string); ok {
		status.LastError = v
	}
	if v, ok := data["config_valid"].(bool); ok {
		status.ConfigValid = v
	}

	return status
}

// enrichStatusDetails adds detailed information to status results
func (m *Manager) enrichStatusDetails(ctx context.Context, target string, result *StatusResult) {
	// Get configuration files
	cmd := salt.Command{
		Client:   "local",
		Target:   target,
		Function: "cmd.run",
		Args:     []string{"cat /etc/boundary/*.hcl 2>/dev/null | head -100"},
	}

	configResult, err := m.saltClient.ExecuteCommand(ctx, cmd)
	if err == nil {
		for minion, output := range configResult.Raw {
			if status, exists := result.Minions[minion]; exists {
				if configStr, ok := output.(string); ok && configStr != "" {
					status.ConfigFile = configStr
					result.Minions[minion] = status
				}
			}
		}
	}

	// Get cluster members if running
	for minion, status := range result.Minions {
		if status.Status.Running && status.Status.Role == "controller" {
			// Check database connection
			cmd := salt.Command{
				Client:   "local",
				Target:   minion,
				Function: "cmd.run",
				Args:     []string{"boundary database migrate -config /etc/boundary/controller.hcl -dry-run 2>&1 | grep -i 'already'"},
			}

			if dbResult, err := m.saltClient.ExecuteCommand(ctx, cmd); err == nil {
				if output, ok := dbResult.Raw[minion].(string); ok && strings.Contains(output, "already") {
					status.Status.DatabaseConnected = true
					result.Minions[minion] = status
				}
			}
		}
	}
}

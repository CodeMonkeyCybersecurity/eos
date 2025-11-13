// pkg/environment/config.go
// Multi-environment configuration management for Eos

package environment

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// DeploymentEnvironment represents an Eos deployment environment configuration
type DeploymentEnvironment struct {
	Name            string           `yaml:"name" json:"name"`
	Datacenter      string           `yaml:"datacenter" json:"datacenter"`
	FrontendHost    string           `yaml:"frontend_host" json:"frontend_host"`
	BackendHost     string           `yaml:"backend_host" json:"backend_host"`
	WireGuard       WireGuardConfig  `yaml:"wireguard" json:"wireguard"`
	Consul          ConsulConfig     `yaml:"consul" json:"consul"`
	Vault           *VaultConfig     `yaml:"vault,omitempty" json:"vault,omitempty"`
	Nomad           *NomadConfig     `yaml:"nomad,omitempty" json:"nomad,omitempty"`
	CreatedAt       string           `yaml:"created_at" json:"created_at"`
	UpdatedAt       string           `yaml:"updated_at" json:"updated_at"`
}

// WireGuardConfig holds WireGuard network configuration
type WireGuardConfig struct {
	Interface      string   `yaml:"interface" json:"interface"`
	Subnet         string   `yaml:"subnet" json:"subnet"`
	FrontendIP     string   `yaml:"frontend_ip" json:"frontend_ip"`
	BackendIP      string   `yaml:"backend_ip" json:"backend_ip"`
	ListenPort     int      `yaml:"listen_port" json:"listen_port"`
	AllowedIPs     []string `yaml:"allowed_ips" json:"allowed_ips"`
}

// ConsulConfig holds Consul configuration
type ConsulConfig struct {
	ServerAddress  string   `yaml:"server_address" json:"server_address"`
	ClientAddress  string   `yaml:"client_address" json:"client_address"`
	Datacenter     string   `yaml:"datacenter" json:"datacenter"`
	RetryJoin      []string `yaml:"retry_join" json:"retry_join"`
	UIEnabled      bool     `yaml:"ui_enabled" json:"ui_enabled"`
}

// VaultConfig holds Vault configuration
type VaultConfig struct {
	Address       string `yaml:"address" json:"address"`
	TLSEnabled    bool   `yaml:"tls_enabled" json:"tls_enabled"`
	SealType      string `yaml:"seal_type" json:"seal_type"` // shamir, auto
	HAEnabled     bool   `yaml:"ha_enabled" json:"ha_enabled"`
}

// NomadConfig holds Nomad configuration
type NomadConfig struct {
	Address       string   `yaml:"address" json:"address"`
	ServerEnabled bool     `yaml:"server_enabled" json:"server_enabled"`
	ClientEnabled bool     `yaml:"client_enabled" json:"client_enabled"`
	Datacenters   []string `yaml:"datacenters" json:"datacenters"`
}

// EnvironmentManager manages environment configurations
type EnvironmentManager struct {
	configDir    string
	consulClient *api.Client
	logger       otelzap.LoggerWithCtx
}

// NewEnvironmentManager creates a new environment manager
func NewEnvironmentManager(rc *eos_io.RuntimeContext) (*EnvironmentManager, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Use ~/.eos/environments for config storage
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	configDir := filepath.Join(homeDir, ".eos", "environments")
	if err := os.MkdirAll(configDir, shared.ServiceDirPerm); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	// Connect to Consul (may fail if not bootstrapped yet, that's ok)
	consulClient, _ := api.NewClient(api.DefaultConfig())

	return &EnvironmentManager{
		configDir:    configDir,
		consulClient: consulClient,
		logger:       logger,
	}, nil
}

// SaveEnvironment saves an environment configuration
// This is idempotent - safe to call multiple times
func (em *EnvironmentManager) SaveEnvironment(ctx context.Context, env *DeploymentEnvironment) error {
	logger := em.logger

	// ASSESS - Check if environment already exists
	configPath := filepath.Join(em.configDir, fmt.Sprintf("%s.yaml", env.Name))
	if _, err := os.Stat(configPath); err == nil {
		logger.Info("Environment config already exists, updating",
			zap.String("environment", env.Name),
			zap.String("path", configPath))
	}

	// INTERVENE - Write to local file
	data, err := yaml.Marshal(env)
	if err != nil {
		return fmt.Errorf("failed to marshal environment config: %w", err)
	}

	if err := os.WriteFile(configPath, data, shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("failed to write environment config: %w", err)
	}

	logger.Info("Environment config saved locally",
		zap.String("environment", env.Name),
		zap.String("path", configPath))

	// Also store in Consul K/V if available
	if em.consulClient != nil {
		if err := em.storeInConsul(ctx, env); err != nil {
			logger.Warn("Failed to store in Consul K/V (non-critical)",
				zap.Error(err))
		}
	}

	return nil
}

// LoadEnvironment loads an environment configuration
func (em *EnvironmentManager) LoadEnvironment(ctx context.Context, name string) (*DeploymentEnvironment, error) {
	logger := em.logger

	// Try Consul first (if available)
	if em.consulClient != nil {
		if env, err := em.loadFromConsul(ctx, name); err == nil {
			logger.Debug("Loaded environment from Consul",
				zap.String("environment", name))
			return env, nil
		}
	}

	// Fallback to local file
	configPath := filepath.Join(em.configDir, fmt.Sprintf("%s.yaml", name))
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read environment config: %w", err)
	}

	var env DeploymentEnvironment
	if err := yaml.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("failed to unmarshal environment config: %w", err)
	}

	logger.Info("Loaded environment from local file",
		zap.String("environment", name),
		zap.String("path", configPath))

	return &env, nil
}

// ListEnvironments lists all configured environments
func (em *EnvironmentManager) ListEnvironments() ([]string, error) {
	entries, err := os.ReadDir(em.configDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read config directory: %w", err)
	}

	var environments []string
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".yaml" {
			name := entry.Name()[:len(entry.Name())-5] // Remove .yaml
			environments = append(environments, name)
		}
	}

	return environments, nil
}

// DetectCurrentEnvironment detects which environment the current host belongs to
func (em *EnvironmentManager) DetectCurrentEnvironment(ctx context.Context) (*DeploymentEnvironment, error) {
	logger := em.logger

	// Try Consul K/V first
	if em.consulClient != nil {
		pair, _, err := em.consulClient.KV().Get("eos/config/current_environment", nil)
		if err == nil && pair != nil {
			envName := string(pair.Value)
			logger.Debug("Detected environment from Consul K/V",
				zap.String("environment", envName))
			return em.LoadEnvironment(ctx, envName)
		}
	}

	// Try hostname detection
	hostname, err := os.Hostname()
	if err == nil {
		logger.Debug("Attempting environment detection from hostname",
			zap.String("hostname", hostname))

		// Load all environments and match by hostname
		envNames, err := em.ListEnvironments()
		if err != nil {
			return nil, err
		}

		for _, name := range envNames {
			env, err := em.LoadEnvironment(ctx, name)
			if err != nil {
				continue
			}

			// Check if current host matches frontend or backend
			if hostname == env.FrontendHost || hostname == env.BackendHost {
				logger.Info("Detected environment from hostname match",
					zap.String("environment", env.Name),
					zap.String("hostname", hostname))
				return env, nil
			}
		}
	}

	return nil, fmt.Errorf("could not detect current environment")
}

// SetCurrentEnvironment marks an environment as the current/active one
func (em *EnvironmentManager) SetCurrentEnvironment(ctx context.Context, envName string) error {
	logger := em.logger

	// Verify environment exists
	if _, err := em.LoadEnvironment(ctx, envName); err != nil {
		return fmt.Errorf("environment %s not found: %w", envName, err)
	}

	// Store in Consul if available
	if em.consulClient != nil {
		pair := &api.KVPair{
			Key:   "eos/config/current_environment",
			Value: []byte(envName),
		}

		if _, err := em.consulClient.KV().Put(pair, nil); err != nil {
			return fmt.Errorf("failed to set current environment in Consul: %w", err)
		}

		logger.Info("Set current environment in Consul",
			zap.String("environment", envName))
	}

	// Also write to local marker file
	markerPath := filepath.Join(em.configDir, ".current")
	if err := os.WriteFile(markerPath, []byte(envName), shared.ConfigFilePerm); err != nil {
		logger.Warn("Failed to write local environment marker",
			zap.Error(err))
	}

	return nil
}

// Helper: Store environment in Consul K/V
func (em *EnvironmentManager) storeInConsul(ctx context.Context, env *DeploymentEnvironment) error {
	data, err := yaml.Marshal(env)
	if err != nil {
		return err
	}

	kvKey := fmt.Sprintf("eos/environments/%s", env.Name)
	pair := &api.KVPair{
		Key:   kvKey,
		Value: data,
	}

	if _, err := em.consulClient.KV().Put(pair, nil); err != nil {
		return err
	}

	// Also store individual config keys for easy access
	configKeys := map[string]string{
		fmt.Sprintf("eos/config/%s/vault_address", env.Datacenter):  env.Vault.Address,
		fmt.Sprintf("eos/config/%s/consul_address", env.Datacenter): env.Consul.ServerAddress,
		fmt.Sprintf("eos/config/%s/frontend_host", env.Datacenter):  env.FrontendHost,
		fmt.Sprintf("eos/config/%s/backend_host", env.Datacenter):   env.BackendHost,
	}

	if env.Nomad != nil {
		configKeys[fmt.Sprintf("eos/config/%s/nomad_address", env.Datacenter)] = env.Nomad.Address
	}

	for key, value := range configKeys {
		if value == "" {
			continue
		}
		pair := &api.KVPair{
			Key:   key,
			Value: []byte(value),
		}
		_, _ = em.consulClient.KV().Put(pair, nil)
	}

	return nil
}

// Helper: Load environment from Consul K/V
func (em *EnvironmentManager) loadFromConsul(ctx context.Context, name string) (*DeploymentEnvironment, error) {
	kvKey := fmt.Sprintf("eos/environments/%s", name)
	pair, _, err := em.consulClient.KV().Get(kvKey, nil)
	if err != nil {
		return nil, err
	}

	if pair == nil {
		return nil, fmt.Errorf("environment %s not found in Consul", name)
	}

	var env DeploymentEnvironment
	if err := yaml.Unmarshal(pair.Value, &env); err != nil {
		return nil, err
	}

	return &env, nil
}

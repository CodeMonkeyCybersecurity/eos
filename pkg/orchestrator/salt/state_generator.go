// pkg/orchestrator/salt/state_generator.go
package salt

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/orchestrator"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"gopkg.in/yaml.v3"
)

// StateDefinition represents a single Salt state
type StateDefinition struct {
	Type       string                 `yaml:"-"`
	Name       string                 `yaml:"-"`
	Properties map[string]interface{} `yaml:",inline"`
}

// SaltState represents a complete Salt state file
type SaltState struct {
	ID     string                    `yaml:"-"`
	States map[string]StateDefinition `yaml:",inline"`
}

// StateGenerator generates Salt states for components
type StateGenerator struct {
	baseDir string
}

// NewStateGenerator creates a new Salt state generator
func NewStateGenerator(baseDir string) *StateGenerator {
	return &StateGenerator{
		baseDir: baseDir,
	}
}

// GenerateState generates Salt states for a component
func (sg *StateGenerator) GenerateState(component orchestrator.Component) (interface{}, error) {
	switch component.Type {
	case orchestrator.ServiceType:
		return sg.generateServiceState(component)
	case orchestrator.ConfigType:
		return sg.generateConfigState(component)
	default:
		return nil, fmt.Errorf("unsupported component type: %s", component.Type)
	}
}

// generateServiceState generates states for service components
func (sg *StateGenerator) generateServiceState(component orchestrator.Component) (*SaltState, error) {
	switch component.Name {
	case "consul":
		return sg.generateConsulState(component)
	case "vault":
		return sg.generateVaultState(component)
	case "nomad":
		return sg.generateNomadState(component)
	default:
		return nil, fmt.Errorf("unsupported service: %s", component.Name)
	}
}

// generateConsulState generates Salt states for Consul
func (sg *StateGenerator) generateConsulState(component orchestrator.Component) (*SaltState, error) {
	config, ok := component.Config.(orchestrator.ConsulConfig)
	if !ok {
		return nil, fmt.Errorf("invalid config type for consul")
	}

	states := make(map[string]StateDefinition)

	// User creation state
	states["consul_user"] = StateDefinition{
		Type: "user.present",
		Name: "consul",
		Properties: map[string]interface{}{
			"name":       "consul",
			"system":     true,
			"shell":      "/bin/false",
			"home":       "/etc/consul.d",
			"createhome": false,
			"comment":    "Consul service account",
		},
	}

	// Directory creation states
	states["consul_directories"] = StateDefinition{
		Type: "file.directory",
		Properties: map[string]interface{}{
			"names": []string{
				"/etc/consul.d",
				"/etc/consul.d/scripts",
				"/opt/consul",
				"/opt/consul/data",
				"/var/log/consul",
			},
			"user":       "consul",
			"group":      "consul",
			"mode":       "0750",
			"makedirs":   true,
			"require": []map[string]string{
				{"user": "consul_user"},
			},
		},
	}

	// Binary installation state
	states["consul_binary"] = StateDefinition{
		Type: "file.managed",
		Properties: map[string]interface{}{
			"name":     "/usr/local/bin/consul",
			"source":   fmt.Sprintf("salt://consul/files/consul_%s", component.Version),
			"mode":     "0755",
			"user":     "root",
			"group":    "root",
			"unless":   fmt.Sprintf("test -f /usr/local/bin/consul && /usr/local/bin/consul version | grep -q %s", component.Version),
		},
	}

	// Configuration file state
	states["consul_config"] = StateDefinition{
		Type: "file.managed",
		Properties: map[string]interface{}{
			"name":     "/etc/consul.d/consul.hcl",
			"source":   "salt://consul/files/consul.hcl.j2",
			"template": "jinja",
			"user":     "consul",
			"group":    "consul",
			"mode":     "0640",
			"context": map[string]interface{}{
				"datacenter":       config.Datacenter,
				"bootstrap_expect": config.BootstrapExpect,
				"ui_enabled":       config.UIEnabled,
				"server_mode":      config.ServerMode,
				"http_port":        shared.PortConsul, // Use centralized port
				"dns_port":         config.Ports.DNS,
				"encryption_key":   config.EncryptionKey,
				"tls_enabled":      config.TLSEnabled,
			},
			"require": []map[string]string{
				{"file": "consul_directories"},
			},
		},
	}

	// Systemd service state
	states["consul_service_file"] = StateDefinition{
		Type: "file.managed",
		Properties: map[string]interface{}{
			"name":     "/etc/systemd/system/consul.service",
			"source":   "salt://consul/files/consul.service.j2",
			"template": "jinja",
			"context": map[string]interface{}{
				"consul_user":  "consul",
				"consul_group": "consul",
			},
		},
	}

	// Service running state
	states["consul_service_running"] = StateDefinition{
		Type: "service.running",
		Properties: map[string]interface{}{
			"name":   "consul",
			"enable": true,
			"watch": []map[string]string{
				{"file": "consul_config"},
				{"file": "consul_service_file"},
			},
			"require": []map[string]string{
				{"file": "consul_binary"},
				{"file": "consul_config"},
				{"file": "consul_service_file"},
			},
		},
	}

	// Vault integration if enabled
	if config.VaultIntegration {
		states["consul_vault_service"] = StateDefinition{
			Type: "file.managed",
			Properties: map[string]interface{}{
				"name":     "/etc/consul.d/vault-service.json",
				"source":   "salt://consul/files/vault-service.json.j2",
				"template": "jinja",
				"user":     "consul",
				"group":    "consul",
				"mode":     "0640",
				"context": map[string]interface{}{
					"vault_addr": config.VaultAddr,
				},
				"require": []map[string]string{
					{"file": "consul_directories"},
				},
			},
		}
	}

	return &SaltState{
		ID:     fmt.Sprintf("consul-%s", config.Datacenter),
		States: states,
	}, nil
}

// generateVaultState generates Salt states for Vault
func (sg *StateGenerator) generateVaultState(component orchestrator.Component) (*SaltState, error) {
	// TODO: Implement Vault state generation
	return nil, fmt.Errorf("vault state generation not implemented")
}

// generateNomadState generates Salt states for Nomad
func (sg *StateGenerator) generateNomadState(component orchestrator.Component) (*SaltState, error) {
	// TODO: Implement Nomad state generation
	return nil, fmt.Errorf("nomad state generation not implemented")
}

// generateConfigState generates states for configuration components
func (sg *StateGenerator) generateConfigState(component orchestrator.Component) (*SaltState, error) {
	// TODO: Implement config state generation
	return nil, fmt.Errorf("config state generation not implemented")
}

// ValidateState validates a Salt state
func (sg *StateGenerator) ValidateState(state interface{}) error {
	saltState, ok := state.(*SaltState)
	if !ok {
		return fmt.Errorf("invalid state type")
	}

	if saltState.ID == "" {
		return fmt.Errorf("state ID cannot be empty")
	}

	if len(saltState.States) == 0 {
		return fmt.Errorf("state must contain at least one state definition")
	}

	// Validate each state definition
	for name, def := range saltState.States {
		if def.Type == "" {
			return fmt.Errorf("state '%s' missing type", name)
		}
		if def.Properties == nil {
			return fmt.Errorf("state '%s' missing properties", name)
		}
	}

	return nil
}

// PreviewState returns a YAML preview of the state
func (sg *StateGenerator) PreviewState(state interface{}) (string, error) {
	saltState, ok := state.(*SaltState)
	if !ok {
		return "", fmt.Errorf("invalid state type")
	}

	// Convert to YAML format
	yamlData := make(map[string]interface{})
	
	for name, def := range saltState.States {
		stateData := make(map[string]interface{})
		stateData[def.Type] = def.Properties
		yamlData[name] = stateData
	}

	output, err := yaml.Marshal(yamlData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal state to YAML: %w", err)
	}

	return string(output), nil
}

// GeneratePillarData generates Salt pillar data for a component
func (sg *StateGenerator) GeneratePillarData(component orchestrator.Component) (map[string]interface{}, error) {
	pillar := make(map[string]interface{})

	switch component.Name {
	case "consul":
		config, ok := component.Config.(orchestrator.ConsulConfig)
		if !ok {
			return nil, fmt.Errorf("invalid config type for consul")
		}

		pillar["consul"] = map[string]interface{}{
			"datacenter":       config.Datacenter,
			"server":           config.ServerMode,
			"bootstrap_expect": config.BootstrapExpect,
			"ui_config": map[string]interface{}{
				"enabled": config.UIEnabled,
			},
			"ports": map[string]interface{}{
				"http": shared.PortConsul,
				"dns":  config.Ports.DNS,
			},
			"encrypt": config.EncryptionKey,
			"tls": map[string]interface{}{
				"enabled": config.TLSEnabled,
			},
		}

		if config.VaultIntegration {
			pillar["consul"].(map[string]interface{})["vault"] = map[string]interface{}{
				"address": config.VaultAddr,
				"enabled": true,
			}
		}

	default:
		return nil, fmt.Errorf("unsupported component: %s", component.Name)
	}

	return pillar, nil
}

// SaveStateFile saves a Salt state to a file
func (sg *StateGenerator) SaveStateFile(state *SaltState, filename string) error {
	preview, err := sg.PreviewState(state)
	if err != nil {
		return fmt.Errorf("failed to preview state: %w", err)
	}

	// TODO: Implement file saving logic
	// This would typically save to the Salt file roots
	_ = preview // Suppress unused variable warning
	
	return nil
}

// GenerateOrchestrationFile generates a Salt orchestration file for complex deployments
func (sg *StateGenerator) GenerateOrchestrationFile(components []orchestrator.Component) (string, error) {
	var orch strings.Builder
	
	orch.WriteString("# Salt orchestration for multi-component deployment\n\n")
	
	for i, component := range components {
		orch.WriteString(fmt.Sprintf("deploy_%s:\n", component.Name))
		orch.WriteString("  salt.state:\n")
		orch.WriteString(fmt.Sprintf("    - tgt: '*'\n"))
		orch.WriteString(fmt.Sprintf("    - sls: %s.install\n", component.Name))
		
		if i > 0 {
			orch.WriteString("    - require:\n")
			orch.WriteString(fmt.Sprintf("      - salt: deploy_%s\n", components[i-1].Name))
		}
		
		orch.WriteString("\n")
	}
	
	return orch.String(), nil
}
// pkg/infrastructure/network/tailscale.go

package network

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/terraform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	cerr "github.com/cockroachdb/errors"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// TailscaleConfig defines the configuration for Tailscale deployment
type TailscaleConfig struct {
	AuthKey          string            // Tailscale auth key (stored in Vault)
	Hostname         string            // Custom hostname for this node
	AdvertiseRoutes  []string          // Subnet routes to advertise
	AcceptRoutes     bool              // Accept routes from other nodes
	Tags             []string          // Tailscale tags for ACL policies
	TerraformDir     string            // Directory for Terraform configuration
	VaultPath        string            // Vault path for storing Tailscale secrets
	ExtraArgs        []string          // Additional arguments for tailscale up
	UseAdvertiseExit bool              // Advertise as an exit node
	UseShield        bool              // Enable Tailscale Shield
	Metadata         map[string]string // Additional metadata
}

// TailscaleDeployment represents a Tailscale deployment state
type TailscaleDeployment struct {
	Config           *TailscaleConfig
	IsInstalled      bool
	IsConnected      bool
	NodeKey          string
	TailnetLocked    bool
	AuthKeyValid     bool
	AdvertisedRoutes []string
	Tags             []string
	ExitNode         bool
}

// DeployTailscaleInfrastructure implements the complete Tailscale deployment following assessment→intervention→evaluation
func DeployTailscaleInfrastructure(rc *eos_io.RuntimeContext, config *TailscaleConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Tailscale infrastructure deployment",
		zap.String("hostname", config.Hostname),
		zap.Strings("advertise_routes", config.AdvertiseRoutes))

	// Assessment: Check current state and prerequisites
	deployment, err := AssessTailscaleState(rc, config)
	if err != nil {
		return cerr.Wrap(err, "Tailscale state assessment failed")
	}

	// Intervention: Deploy Tailscale infrastructure using Terraform and direct installation
	if err := interventionDeployTailscale(rc, config, deployment); err != nil {
		return cerr.Wrap(err, "Tailscale deployment intervention failed")
	}

	// Evaluation: Verify deployment and functionality
	return EvaluateTailscaleDeployment(rc, config)
}

// AssessTailscaleState checks the current Tailscale installation and network state
func AssessTailscaleState(rc *eos_io.RuntimeContext, config *TailscaleConfig) (*TailscaleDeployment, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Assessing Tailscale deployment state")

	deployment := &TailscaleDeployment{
		Config:           config,
		IsInstalled:      false,
		IsConnected:      false,
		AuthKeyValid:     false,
		AdvertisedRoutes: []string{},
		Tags:             []string{},
	}

	// Check if Tailscale is installed
	if err := checkTailscaleInstalled(rc); err == nil {
		deployment.IsInstalled = true
		logger.Info("Tailscale is already installed")

		// Check connection status
		status, err := getTailscaleStatus(rc)
		if err == nil {
			deployment.IsConnected = status.Connected
			deployment.NodeKey = status.NodeKey
			deployment.TailnetLocked = status.TailnetLocked
			deployment.AdvertisedRoutes = status.AdvertisedRoutes
			deployment.Tags = status.Tags
			deployment.ExitNode = status.ExitNode

			logger.Info("Tailscale status retrieved",
				zap.Bool("connected", deployment.IsConnected),
				zap.String("node_key", deployment.NodeKey),
				zap.Strings("advertised_routes", deployment.AdvertisedRoutes))
		}
	} else {
		logger.Info("Tailscale is not installed")
	}

	// Check if auth key is available in Vault
	if config.VaultPath != "" {
		if authKey, err := retrieveTailscaleAuthKey(rc, config.VaultPath); err == nil && authKey != "" {
			deployment.AuthKeyValid = true
			config.AuthKey = authKey
			logger.Info("Tailscale auth key retrieved from Vault")
		} else {
			logger.Warn("Tailscale auth key not found in Vault", zap.Error(err))
		}
	}

	// Check system prerequisites
	if err := checkSystemPrerequisites(rc); err != nil {
		logger.Warn("System prerequisites check failed", zap.Error(err))
	}

	logger.Info("Tailscale state assessment completed",
		zap.Bool("installed", deployment.IsInstalled),
		zap.Bool("connected", deployment.IsConnected),
		zap.Bool("auth_key_valid", deployment.AuthKeyValid))

	return deployment, nil
}

// interventionDeployTailscale performs the actual deployment steps
func interventionDeployTailscale(rc *eos_io.RuntimeContext, config *TailscaleConfig, deployment *TailscaleDeployment) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Tailscale deployment intervention")

	// Step 1: Install Tailscale if not already installed
	if !deployment.IsInstalled {
		if err := installTailscale(rc); err != nil {
			return cerr.Wrap(err, "Tailscale installation failed")
		}
		logger.Info("Tailscale installed successfully")
	}

	// Step 2: Generate Terraform configuration for advanced networking
	if config.TerraformDir != "" {
		if err := generateTailscaleTerraformConfig(rc, config); err != nil {
			return cerr.Wrap(err, "Terraform configuration generation failed")
		}

		if err := applyTailscaleTerraformConfig(rc, config); err != nil {
			return cerr.Wrap(err, "Terraform apply failed")
		}
	}

	// Step 3: Configure and connect Tailscale
	if !deployment.IsConnected || needsReconfiguration(config, deployment) {
		if err := configureTailscale(rc, config); err != nil {
			return cerr.Wrap(err, "Tailscale configuration failed")
		}
		logger.Info("Tailscale configured and connected successfully")
	}

	// Step 4: Store configuration in Vault for future reference
	if config.VaultPath != "" {
		if err := storeTailscaleConfigInVault(rc, config); err != nil {
			logger.Warn("Failed to store Tailscale config in Vault", zap.Error(err))
			// Don't fail the deployment for Vault storage issues
		}
	}

	logger.Info("Tailscale deployment intervention completed successfully")
	return nil
}

// EvaluateTailscaleDeployment verifies the deployment is working correctly
func EvaluateTailscaleDeployment(rc *eos_io.RuntimeContext, config *TailscaleConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Evaluating Tailscale deployment")

	// Check installation
	if err := checkTailscaleInstalled(rc); err != nil {
		return cerr.Wrap(err, "Tailscale installation validation failed")
	}

	// Check connection status
	status, err := getTailscaleStatus(rc)
	if err != nil {
		return cerr.Wrap(err, "failed to get Tailscale status")
	}

	if !status.Connected {
		return cerr.New("Tailscale is installed but not connected")
	}

	// Verify advertised routes if specified
	if len(config.AdvertiseRoutes) > 0 {
		for _, route := range config.AdvertiseRoutes {
			if !contains(status.AdvertisedRoutes, route) {
				return cerr.New(fmt.Sprintf("route %s is not being advertised", route))
			}
		}
		logger.Info("All specified routes are being advertised",
			zap.Strings("routes", config.AdvertiseRoutes))
	}

	// Verify tags if specified
	if len(config.Tags) > 0 {
		for _, tag := range config.Tags {
			if !contains(status.Tags, tag) {
				logger.Warn("Tag not applied", zap.String("tag", tag))
			}
		}
	}

	// Test connectivity
	if err := testTailscaleConnectivity(rc); err != nil {
		return cerr.Wrap(err, "Tailscale connectivity test failed")
	}

	logger.Info("Tailscale deployment evaluation completed successfully",
		zap.String("node_key", status.NodeKey),
		zap.Bool("exit_node", status.ExitNode),
		zap.Strings("advertised_routes", status.AdvertisedRoutes))

	return nil
}

// Helper functions and types

type TailscaleStatus struct {
	Connected        bool
	NodeKey          string
	TailnetLocked    bool
	AdvertisedRoutes []string
	Tags             []string
	ExitNode         bool
}

func checkTailscaleInstalled(rc *eos_io.RuntimeContext) error {
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "tailscale",
		Args:    []string{"version"},
		Capture: true,
	})
	return err
}

func getTailscaleStatus(rc *eos_io.RuntimeContext) (*TailscaleStatus, error) {
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "tailscale",
		Args:    []string{"status", "--json"},
		Capture: true,
	})
	if err != nil {
		return nil, err
	}

	// Parse JSON output (simplified for this example)
	status := &TailscaleStatus{
		Connected:        strings.Contains(output, `"Online":true`),
		NodeKey:          extractFieldFromJSON(output, "NodeKey"),
		TailnetLocked:    strings.Contains(output, `"Locked":true`),
		AdvertisedRoutes: []string{}, // Would parse from JSON
		Tags:             []string{}, // Would parse from JSON
		ExitNode:         strings.Contains(output, `"ExitNode":true`),
	}

	return status, nil
}

func installTailscale(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing Tailscale")

	// Download and run the official Tailscale installation script
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "curl",
		Args:    []string{"-fsSL", "https://tailscale.com/install.sh"},
	})
	if err != nil {
		return err
	}

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "sh",
		Args:    []string{"-c", "curl -fsSL https://tailscale.com/install.sh | sh"},
	})
	if err != nil {
		logger.Error("Tailscale installation failed", zap.Error(err), zap.String("output", output))
		return err
	}

	return nil
}

func configureTailscale(rc *eos_io.RuntimeContext, config *TailscaleConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring Tailscale connection")

	args := []string{"up"}

	// Add auth key if available
	if config.AuthKey != "" {
		args = append(args, "--authkey="+config.AuthKey)
	}

	// Add hostname if specified
	if config.Hostname != "" {
		args = append(args, "--hostname="+config.Hostname)
	}

	// Add advertise routes
	if len(config.AdvertiseRoutes) > 0 {
		routes := strings.Join(config.AdvertiseRoutes, ",")
		args = append(args, "--advertise-routes="+routes)
	}

	// Add accept routes
	if config.AcceptRoutes {
		args = append(args, "--accept-routes")
	}

	// Add exit node
	if config.UseAdvertiseExit {
		args = append(args, "--advertise-exit-node")
	}

	// Add shield
	if config.UseShield {
		args = append(args, "--shields-up")
	}

	// Add extra arguments
	args = append(args, config.ExtraArgs...)

	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "tailscale",
		Args:    args,
	})

	if err != nil {
		logger.Error("Tailscale configuration failed", zap.Error(err))
		return err
	}

	return nil
}

func generateTailscaleTerraformConfig(rc *eos_io.RuntimeContext, config *TailscaleConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Generating Tailscale Terraform configuration")

	if err := os.MkdirAll(config.TerraformDir, shared.ServiceDirPerm); err != nil {
		return err
	}

	// Main Terraform configuration
	mainTF := `
terraform {
  required_providers {
    tailscale = {
      source  = "tailscale/tailscale"
      version = "~> 0.13"
    }
  }
}

provider "tailscale" {
  api_key = var.tailscale_api_key
  tailnet = var.tailnet
}

variable "tailscale_api_key" {
  description = "Tailscale API key"
  type        = string
  sensitive   = true
}

variable "tailnet" {
  description = "Tailscale tailnet name"
  type        = string
}

variable "hostname" {
  description = "Device hostname"
  type        = string
  default     = "{{ .Hostname }}"
}

variable "advertise_routes" {
  description = "Routes to advertise"
  type        = list(string)
  default     = {{ .AdvertiseRoutesJSON }}
}

variable "tags" {
  description = "Device tags"
  type        = list(string)
  default     = {{ .TagsJSON }}
}

resource "tailscale_device_key" "auth_key" {
  reusable      = true
  ephemeral     = false
  preauthorized = true
  expiry        = 3600
  description   = "Auth key for {{ .Hostname }}"
}

resource "tailscale_device_tags" "device_tags" {
  device_id = tailscale_device_key.auth_key.device_id
  tags      = var.tags
}

output "auth_key" {
  value     = tailscale_device_key.auth_key.key
  sensitive = true
}

output "device_id" {
  value = tailscale_device_key.auth_key.device_id
}
`

	// Create Terraform manager and generate configuration
	tfManager := terraform.NewManager(rc, config.TerraformDir)

	templateData := struct {
		Hostname            string
		AdvertiseRoutesJSON string
		TagsJSON            string
	}{
		Hostname:            config.Hostname,
		AdvertiseRoutesJSON: formatStringSliceAsJSON(config.AdvertiseRoutes),
		TagsJSON:            formatStringSliceAsJSON(config.Tags),
	}

	if err := tfManager.GenerateFromString(mainTF, "main.tf", templateData); err != nil {
		return err
	}

	logger.Info("Tailscale Terraform configuration generated")
	return nil
}

func applyTailscaleTerraformConfig(rc *eos_io.RuntimeContext, config *TailscaleConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Applying Tailscale Terraform configuration")

	tfManager := terraform.NewManager(rc, config.TerraformDir)

	// Set variables from Vault
	if config.VaultPath != "" {
		if apiKey, err := vault.ReadSecret(rc, config.VaultPath+"/api_key"); err == nil {
			if data, ok := apiKey.Data["data"].(map[string]interface{}); ok {
				if key, ok := data["api_key"].(string); ok {
					tfManager.SetVariable("tailscale_api_key", key)
				}
			}
		}

		if tailnet, err := vault.ReadSecret(rc, config.VaultPath+"/tailnet"); err == nil {
			if data, ok := tailnet.Data["data"].(map[string]interface{}); ok {
				if tn, ok := data["tailnet"].(string); ok {
					tfManager.SetVariable("tailnet", tn)
				}
			}
		}
	}

	// Initialize, plan, and apply
	if err := tfManager.Init(rc); err != nil {
		return err
	}

	if err := tfManager.Validate(rc); err != nil {
		return err
	}

	if err := tfManager.Plan(rc); err != nil {
		return err
	}

	if err := tfManager.Apply(rc, true); err != nil {
		return err
	}

	// Retrieve the generated auth key
	authKey, err := tfManager.Output(rc, "auth_key")
	if err == nil && authKey != "" {
		config.AuthKey = authKey
		logger.Info("Auth key retrieved from Terraform output")
	}

	return nil
}

func checkSystemPrerequisites(rc *eos_io.RuntimeContext) error {
	// Check if running as root or with sudo capabilities
	if os.Geteuid() != 0 {
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "sudo",
			Args:    []string{"-n", "true"},
		})
		if err != nil {
			return cerr.New("Tailscale installation requires root privileges or sudo access")
		}
	}

	// Check internet connectivity
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ping",
		Args:    []string{"-c", "1", "login.tailscale.com"},
	})
	if err != nil {
		return cerr.New("unable to reach Tailscale servers - check internet connectivity")
	}

	return nil
}

func needsReconfiguration(config *TailscaleConfig, deployment *TailscaleDeployment) bool {
	// Check if advertised routes have changed
	if len(config.AdvertiseRoutes) != len(deployment.AdvertisedRoutes) {
		return true
	}

	for _, route := range config.AdvertiseRoutes {
		if !contains(deployment.AdvertisedRoutes, route) {
			return true
		}
	}

	// Check if tags have changed
	if len(config.Tags) != len(deployment.Tags) {
		return true
	}

	for _, tag := range config.Tags {
		if !contains(deployment.Tags, tag) {
			return true
		}
	}

	return false
}

func testTailscaleConnectivity(rc *eos_io.RuntimeContext) error {
	// Test basic connectivity by pinging the coordination server
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "tailscale",
		Args:    []string{"ping", "--verbose", "login.tailscale.com"},
	})
	return err
}

func retrieveTailscaleAuthKey(rc *eos_io.RuntimeContext, vaultPath string) (string, error) {
	secret, err := vault.ReadSecret(rc, fmt.Sprintf("secret/data/%s/auth_key", vaultPath))
	if err != nil {
		return "", err
	}

	if secret.Data != nil {
		if data, ok := secret.Data["data"].(map[string]interface{}); ok {
			if authKey, ok := data["auth_key"].(string); ok {
				return authKey, nil
			}
		}
	}

	return "", cerr.New("auth key not found in Vault")
}

func storeTailscaleConfigInVault(rc *eos_io.RuntimeContext, config *TailscaleConfig) error {
	client, err := vault.GetVaultClient(rc)
	if err != nil {
		return err
	}

	configData := map[string]interface{}{
		"hostname":         config.Hostname,
		"advertise_routes": config.AdvertiseRoutes,
		"accept_routes":    config.AcceptRoutes,
		"tags":             config.Tags,
		"use_exit_node":    config.UseAdvertiseExit,
		"use_shield":       config.UseShield,
	}

	return vault.WriteKVv2(rc, client, "secret", fmt.Sprintf("%s/config", config.VaultPath), configData)
}

// Utility functions

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func extractFieldFromJSON(jsonStr, field string) string {
	// Simplified JSON field extraction - in production, use proper JSON parsing
	lines := strings.Split(jsonStr, "\n")
	for _, line := range lines {
		if strings.Contains(line, fmt.Sprintf(`"%s"`, field)) {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				value := strings.Trim(parts[1], ` ",`)
				return value
			}
		}
	}
	return ""
}

func formatStringSliceAsJSON(slice []string) string {
	if len(slice) == 0 {
		return "[]"
	}

	quoted := make([]string, len(slice))
	for i, s := range slice {
		quoted[i] = fmt.Sprintf(`"%s"`, s)
	}

	return fmt.Sprintf("[%s]", strings.Join(quoted, ", "))
}

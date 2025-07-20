// pkg/helen/ghost.go
// Ghost CMS specific functionality for Helen deployments
// This file extends the existing helen package to support Ghost CMS

package helen

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// GhostConfig extends the base Config for Ghost-specific settings
type GhostConfig struct {
	*Config // Embed the existing Config struct
	
	// Ghost-specific fields
	Mode          string   `json:"mode"`
	Domain        string   `json:"domain"`
	Environment   string   `json:"environment"`
	Database      string   `json:"database"`
	GitRepo       string   `json:"git_repo,omitempty"`
	GitBranch     string   `json:"git_branch"`
	RepoPath      string   `json:"repo_path,omitempty"`
	EnableAuth    bool     `json:"enable_auth"`
	EnableWebhook bool     `json:"enable_webhook"`
	DockerImage   string   `json:"docker_image"`
	InstanceCount int      `json:"instance_count"`
	VaultPaths    VaultPaths `json:"vault_paths"`
	
	// Database configuration
	DBHost     string `json:"db_host,omitempty"`
	DBPort     int    `json:"db_port,omitempty"`
	DBName     string `json:"db_name,omitempty"`
	DBUser     string `json:"db_user,omitempty"`
	DBPassword string `json:"db_password,omitempty"`
	
	// Email configuration
	MailHost     string `json:"mail_host,omitempty"`
	MailPort     int    `json:"mail_port,omitempty"`
	MailUser     string `json:"mail_user,omitempty"`
	MailPassword string `json:"mail_password,omitempty"`
	MailFrom     string `json:"mail_from,omitempty"`
}

// VaultPaths stores the Vault paths for various secrets
type VaultPaths struct {
	Database string `json:"database"`
	Mail     string `json:"mail"`
	S3       string `json:"s3,omitempty"`
	Admin    string `json:"admin"`
}

// ParseGhostFlags parses command flags specific to Ghost deployment
func ParseGhostFlags(cmd *cobra.Command) (*GhostConfig, error) {
	// First parse the base flags using existing function
	baseConfig, err := ParseHelenFlags(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to parse base flags: %w", err)
	}

	// Create GhostConfig with embedded base config
	config := &GhostConfig{
		Config: baseConfig,
	}

	// Parse Ghost-specific flags
	config.Mode = "ghost"
	config.Domain, _ = cmd.Flags().GetString("domain")
	config.Environment, _ = cmd.Flags().GetString("environment")
	config.Database, _ = cmd.Flags().GetString("database")
	config.GitRepo, _ = cmd.Flags().GetString("git-repo")
	config.GitBranch, _ = cmd.Flags().GetString("git-branch")
	config.EnableAuth, _ = cmd.Flags().GetBool("enable-auth")
	config.EnableWebhook, _ = cmd.Flags().GetBool("enable-webhook")
	config.InstanceCount, _ = cmd.Flags().GetInt("ghost-instances")
	
	// Set default Docker image if not specified
	config.DockerImage = "ghost:5-alpine"
	
	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return config, nil
}

// Validate ensures the Ghost configuration is valid
func (c *GhostConfig) Validate() error {
	if c.Domain == "" {
		return fmt.Errorf("domain is required for Ghost deployment")
	}
	
	validEnvs := []string{"dev", "staging", "production"}
	valid := false
	for _, env := range validEnvs {
		if c.Environment == env {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("invalid environment: %s (must be dev/staging/production)", c.Environment)
	}
	
	if c.Database != "mysql" && c.Database != "sqlite" {
		return fmt.Errorf("invalid database: %s (must be mysql or sqlite)", c.Database)
	}
	
	if c.InstanceCount < 1 {
		c.InstanceCount = 1
	}
	
	return nil
}

// CheckGhostPrerequisites verifies all requirements for Ghost deployment
func CheckGhostPrerequisites(rc *eos_io.RuntimeContext, config *GhostConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check base prerequisites first (Vault, Nomad, Consul)
	if err := CheckPrerequisites(rc); err != nil {
		return err
	}
	
	// Check if Hecate is deployed
	logger.Info("Checking Hecate deployment")
	services, err := consulListServices(rc)
	if err != nil {
		return fmt.Errorf("failed to query Consul: %w", err)
	}
	
	hecateFound := false
	for _, service := range services {
		if strings.Contains(service, "hecate") || strings.Contains(service, "caddy") {
			hecateFound = true
			break
		}
	}
	
	if !hecateFound {
		return fmt.Errorf("Hecate reverse proxy not found. Deploy with: eos create hecate")
	}
	
	// Check if database is available (for MySQL mode)
	if config.Database == "mysql" {
		logger.Info("Checking MySQL availability")
		// This would check if MySQL is deployed or accessible
		// For now, we'll assume it needs to be configured
	}
	
	return nil
}

// PrepareGitRepository clones or updates the Helen git repository
func PrepareGitRepository(rc *eos_io.RuntimeContext, config *GhostConfig) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Create work directory
	repoPath := filepath.Join(config.WorkDir, "helen-repo")
	
	// Check if repo already exists
	if _, err := os.Stat(filepath.Join(repoPath, ".git")); err == nil {
		// Repository exists, update it
		logger.Info("Updating existing Helen repository",
			zap.String("path", repoPath),
			zap.String("branch", config.GitBranch))
		
		if err := gitPull(rc, repoPath, config.GitBranch); err != nil {
			return "", fmt.Errorf("failed to update repository: %w", err)
		}
	} else {
		// Clone new repository
		logger.Info("Cloning Helen repository",
			zap.String("repo", config.GitRepo),
			zap.String("branch", config.GitBranch))
		
		if err := gitClone(rc, config.GitRepo, repoPath, config.GitBranch); err != nil {
			return "", fmt.Errorf("failed to clone repository: %w", err)
		}
	}
	
	return repoPath, nil
}

// CreateGhostVaultSecrets creates the necessary Vault secrets for Ghost
func CreateGhostVaultSecrets(rc *eos_io.RuntimeContext, config *GhostConfig) (VaultPaths, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	paths := VaultPaths{
		Database: fmt.Sprintf("kv/data/helen/%s/database", config.Environment),
		Mail:     fmt.Sprintf("kv/data/helen/%s/mail", config.Environment),
		Admin:    fmt.Sprintf("kv/data/helen/%s/admin", config.Environment),
	}
	
	// Create database secrets
	dbSecrets := map[string]interface{}{
		"client":   config.Database,
		"host":     "localhost",
		"port":     3306,
		"user":     fmt.Sprintf("helen_%s", config.Environment),
		"password": generatePassword(),
		"database": fmt.Sprintf("helen_%s", config.Environment),
	}
	
	// Override with MySQL service discovery if available
	if config.Database == "mysql" {
		if mysqlService, err := consulGetService(rc, "mysql"); err == nil {
			dbSecrets["host"] = mysqlService.Address
			dbSecrets["port"] = mysqlService.Port
		}
	}
	
	logger.Info("Creating database secrets in Vault", zap.String("path", paths.Database))
	if err := vaultWriteSecret(rc, paths.Database, dbSecrets); err != nil {
		return paths, fmt.Errorf("failed to create database secrets: %w", err)
	}
	
	// Create mail secrets with sensible defaults
	mailSecrets := map[string]interface{}{
		"host":     "smtp.gmail.com",
		"port":     587,
		"secure":   true,
		"user":     "", // User should configure
		"password": "", // User should configure
		"from":     fmt.Sprintf("noreply@%s", config.Domain),
	}
	
	logger.Info("Creating mail configuration in Vault", zap.String("path", paths.Mail))
	if err := vaultWriteSecret(rc, paths.Mail, mailSecrets); err != nil {
		return paths, fmt.Errorf("failed to create mail secrets: %w", err)
	}
	
	// Create admin user secrets
	adminSecrets := map[string]interface{}{
		"email":    fmt.Sprintf("admin@%s", config.Domain),
		"password": generatePassword(),
		"name":     "Administrator",
	}
	
	logger.Info("Creating admin credentials in Vault", zap.String("path", paths.Admin))
	if err := vaultWriteSecret(rc, paths.Admin, adminSecrets); err != nil {
		return paths, fmt.Errorf("failed to create admin secrets: %w", err)
	}
	
	return paths, nil
}

// DeployGhost deploys Ghost CMS using Nomad
func DeployGhost(rc *eos_io.RuntimeContext, config *GhostConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Generate Nomad job specification
	jobSpec, err := generateGhostNomadJob(config)
	if err != nil {
		return fmt.Errorf("failed to generate Nomad job: %w", err)
	}
	
	// Write job file
	jobFile := filepath.Join(config.WorkDir, fmt.Sprintf("helen-ghost-%s.nomad", config.Environment))
	if err := os.WriteFile(jobFile, jobSpec, 0644); err != nil {
		return fmt.Errorf("failed to write job file: %w", err)
	}
	
	// Deploy using Nomad
	logger.Info("Deploying Ghost to Nomad",
		zap.String("job_file", jobFile),
		zap.String("environment", config.Environment))
	
	if err := nomadRunJob(rc, jobFile); err != nil {
		return fmt.Errorf("failed to deploy Nomad job: %w", err)
	}
	
	// Register with Consul
	if err := registerGhostService(rc, config); err != nil {
		logger.Warn("Failed to register with Consul", zap.Error(err))
	}
	
	return nil
}


// SetupGhostWebhook configures CI/CD webhook for automatic deployments
func SetupGhostWebhook(rc *eos_io.RuntimeContext, config *GhostConfig) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Generate webhook endpoint
	webhookPath := fmt.Sprintf("/webhooks/helen/%s", config.Environment)
	webhookURL := fmt.Sprintf("https://%s%s", config.Domain, webhookPath)
	
	// Create webhook handler configuration
	webhookConfig := map[string]interface{}{
		"endpoint":    webhookPath,
		"environment": config.Environment,
		"git_repo":    config.GitRepo,
		"git_branch":  config.GitBranch,
		"secret":      generatePassword(),
	}
	
	// Store webhook configuration in Vault
	webhookVaultPath := fmt.Sprintf("kv/data/helen/%s/webhook", config.Environment)
	if err := vaultWriteSecret(rc, webhookVaultPath, webhookConfig); err != nil {
		return "", fmt.Errorf("failed to store webhook config: %w", err)
	}
	
	logger.Info("Webhook configuration created",
		zap.String("url", webhookURL),
		zap.String("vault_path", webhookVaultPath))
	
	// TODO: Deploy actual webhook handler service
	// This would be a separate Nomad job that listens for webhooks
	// and triggers redeployments
	
	return webhookURL, nil
}

// WaitForGhostHealthy waits for the Ghost deployment to become healthy
func WaitForGhostHealthy(rc *eos_io.RuntimeContext, config *GhostConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	serviceName := fmt.Sprintf("helen-ghost-%s", config.Environment)
	logger.Info("Waiting for Ghost to become healthy",
		zap.String("service", serviceName))
	
	// Wait up to 5 minutes for service to be healthy
	ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Minute)
	defer cancel()
	
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for Ghost to become healthy")
		case <-ticker.C:
			// Check Consul for service health
			health, err := consulGetServiceHealth(rc, serviceName)
			if err != nil {
				logger.Debug("Health check failed", zap.Error(err))
				continue
			}
			
			if health.Status == "passing" {
				logger.Info("Ghost is healthy")
				return nil
			}
			
			logger.Debug("Ghost not yet healthy",
				zap.String("status", health.Status))
		}
	}
}

// Helper function to generate Nomad job specification
func generateGhostNomadJob(config *GhostConfig) ([]byte, error) {
	// This would use the Nomad job template
	// For now, return a placeholder
	jobTemplate := `
job "helen-ghost-{{ .Environment }}" {
  datacenters = ["dc1"]
  type = "service"
  
  group "ghost" {
    count = {{ .InstanceCount }}
    
    network {
      mode = "bridge"
      port "http" {
        to = 2368
      }
    }
    
    service {
      name = "helen-ghost-{{ .Environment }}"
      port = "http"
      
      check {
        type     = "http"
        path     = "/ghost/api/admin/site/"
        interval = "10s"
        timeout  = "2s"
      }
    }
    
    task "ghost" {
      driver = "docker"
      
      config {
        image = "{{ .DockerImage }}"
        ports = ["http"]
      }
      
      template {
        destination = "secrets/env"
        env = true
        data = <<EOH
NODE_ENV=production
url=https://{{ .Domain }}
EOH
      }
      
      resources {
        cpu    = 500
        memory = 512
      }
    }
  }
}
`
	
	tmpl, err := template.New("nomad-job").Parse(jobTemplate)
	if err != nil {
		return nil, err
	}
	
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, config); err != nil {
		return nil, err
	}
	
	return buf.Bytes(), nil
}

// Helper function to register Ghost service with Consul
func registerGhostService(rc *eos_io.RuntimeContext, config *GhostConfig) error {
	service := &ServiceDefinition{
		Name: fmt.Sprintf("helen-ghost-%s", config.Environment),
		Port: config.Port,
		Tags: []string{
			"ghost",
			"cms",
			config.Environment,
			fmt.Sprintf("domain:%s", config.Domain),
		},
		Check: &ServiceHealthCheck{
			HTTP:     fmt.Sprintf("http://localhost:%d/ghost/api/admin/site/", config.Port),
			Interval: "10s",
			Timeout:  "5s",
		},
	}
	
	return consulRegisterService(rc, service)
}

// Helper function to generate secure passwords
func generatePassword() string {
	// This would use a proper password generator
	// For now, return a placeholder
	return fmt.Sprintf("helen-%s-%d", time.Now().Format("20060102"), time.Now().Unix()%10000)
}
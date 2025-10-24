// pkg/helen/webhook.go
// Webhook functionality for Helen CI/CD integration

package helen

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"os/exec"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// WebhookPayload represents the incoming webhook data
type WebhookPayload struct {
	Repository struct {
		Name     string `json:"name"`
		CloneURL string `json:"clone_url"`
		SSHURL   string `json:"ssh_url"`
	} `json:"repository"`
	Ref        string `json:"ref"`
	After      string `json:"after"`
	HeadCommit struct {
		ID        string   `json:"id"`
		Message   string   `json:"message"`
		Timestamp string   `json:"timestamp"`
		Author    struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		} `json:"author"`
		Added    []string `json:"added"`
		Modified []string `json:"modified"`
		Removed  []string `json:"removed"`
	} `json:"head_commit"`
	Pusher struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"pusher"`
}

// WebhookConfigExtended extends the base WebhookConfig with deployment info
type WebhookConfigExtended struct {
	WebhookConfig
	Environment string    `json:"environment"`
	GitRepo     string    `json:"git_repo"`
	GitBranch   string    `json:"git_branch"`
	CreatedAt   time.Time `json:"created_at"`
	LastTrigger time.Time `json:"last_trigger,omitempty"`
}

// WebhookHandler handles incoming webhook requests for Helen deployments
func WebhookHandler(rc *eos_io.RuntimeContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := otelzap.Ctx(rc.Ctx)
		
		// Extract environment from URL path
		pathParts := strings.Split(r.URL.Path, "/")
		if len(pathParts) < 4 {
			logger.Error("Invalid webhook path", zap.String("path", r.URL.Path))
			http.Error(w, "Invalid webhook path", http.StatusBadRequest)
			return
		}
		environment := pathParts[3]
		
		logger.Info("Webhook received",
			zap.String("environment", environment),
			zap.String("method", r.Method),
			zap.String("remote_addr", r.RemoteAddr))
		
		// Only accept POST requests
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		
		// Read webhook configuration from Vault
		webhookConfig, err := getWebhookConfig(rc, environment)
		if err != nil {
			logger.Error("Failed to get webhook config", zap.Error(err))
			http.Error(w, "Webhook not configured", http.StatusNotFound)
			return
		}
		
		// Verify webhook signature
		signature := r.Header.Get("X-Hub-Signature-256")
		if signature == "" {
			signature = r.Header.Get("X-Signature")
		}
		
		body, err := readAndVerifyWebhook(r, webhookConfig.Secret, signature)
		if err != nil {
			logger.Error("Webhook verification failed", zap.Error(err))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		
		// Parse webhook payload
		var payload WebhookPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			logger.Error("Failed to parse webhook payload", zap.Error(err))
			http.Error(w, "Invalid payload", http.StatusBadRequest)
			return
		}
		
		// Check if this is the correct branch
		expectedRef := fmt.Sprintf("refs/heads/%s", webhookConfig.GitBranch)
		if payload.Ref != expectedRef {
			logger.Info("Ignoring push to non-target branch",
				zap.String("ref", payload.Ref),
				zap.String("expected", expectedRef))
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, "Ignoring push to %s (expecting %s)", payload.Ref, expectedRef)
			return
		}
		
		// Log deployment trigger
		logger.Info("Triggering Helen deployment",
			zap.String("environment", environment),
			zap.String("commit", payload.After),
			zap.String("author", payload.HeadCommit.Author.Name),
			zap.String("message", payload.HeadCommit.Message))
		
		// Trigger deployment asynchronously
		go func() {
			if err := triggerDeployment(rc, environment, &payload); err != nil {
				logger.Error("Deployment failed", zap.Error(err))
			}
		}()
		
		// Update last trigger time
		webhookConfig.LastTrigger = time.Now()
		_ = updateWebhookConfig(rc, environment, webhookConfig)
		
		// Return success
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "Deployment triggered for environment: %s", environment)
	}
}

// readAndVerifyWebhook reads the request body and verifies the signature
func readAndVerifyWebhook(r *http.Request, secret, signature string) ([]byte, error) {
	body := make([]byte, r.ContentLength)
	_, err := r.Body.Read(body)
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}
	defer func() { _ = r.Body.Close() }()
	
	// Verify signature if provided
	if signature != "" && secret != "" {
		if !verifySignature(body, secret, signature) {
			return nil, fmt.Errorf("invalid signature")
		}
	}
	
	return body, nil
}

// verifySignature verifies the webhook signature
func verifySignature(payload []byte, secret, signature string) bool {
	// Remove "sha256=" prefix if present
	signature = strings.TrimPrefix(signature, "sha256=")
	
	// Calculate expected signature
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expectedSig := hex.EncodeToString(mac.Sum(nil))
	
	// Constant time comparison
	return hmac.Equal([]byte(signature), []byte(expectedSig))
}

// getWebhookConfig retrieves webhook configuration from Vault
func getWebhookConfig(rc *eos_io.RuntimeContext, environment string) (*WebhookConfigExtended, error) {
	vaultPath := fmt.Sprintf("kv/data/helen/%s/webhook", environment)
	
	data, err := vaultReadSecret(rc, vaultPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read webhook config: %w", err)
	}
	
	config := &WebhookConfigExtended{
		WebhookConfig: WebhookConfig{
			Secret: data["secret"].(string),
		},
		Environment: data["environment"].(string),
		GitRepo:     data["git_repo"].(string),
		GitBranch:   data["git_branch"].(string),
	}
	
	// Parse timestamps if present
	if createdAt, ok := data["created_at"].(string); ok {
		config.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	}
	if lastTrigger, ok := data["last_trigger"].(string); ok {
		config.LastTrigger, _ = time.Parse(time.RFC3339, lastTrigger)
	}
	
	return config, nil
}

// updateWebhookConfig updates webhook configuration in Vault
func updateWebhookConfig(rc *eos_io.RuntimeContext, environment string, config *WebhookConfigExtended) error {
	vaultPath := fmt.Sprintf("kv/data/helen/%s/webhook", environment)
	
	data := map[string]interface{}{
		"secret":       config.Secret,
		"environment":  config.Environment,
		"git_repo":     config.GitRepo,
		"git_branch":   config.GitBranch,
		"created_at":   config.CreatedAt.Format(time.RFC3339),
		"last_trigger": config.LastTrigger.Format(time.RFC3339),
	}
	
	return vaultWriteSecret(rc, vaultPath, data)
}

// triggerDeployment triggers a new deployment for Helen
func triggerDeployment(rc *eos_io.RuntimeContext, environment string, payload *WebhookPayload) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Starting deployment",
		zap.String("environment", environment),
		zap.String("commit", payload.After))
	
	// Create deployment context
	deployCtx := &DeploymentContext{
		Environment: environment,
		CommitID:    payload.After,
		CommitMsg:   payload.HeadCommit.Message,
		Author:      payload.HeadCommit.Author.Name,
		Timestamp:   time.Now(),
	}
	
	// Read current configuration
	ghostConfig, err := readGhostConfig(rc, environment)
	if err != nil {
		return fmt.Errorf("failed to read Ghost config: %w", err)
	}
	
	// Update git repository
	logger.Info("Updating git repository")
	if err := updateGitRepository(rc, ghostConfig); err != nil {
		return fmt.Errorf("failed to update repository: %w", err)
	}
	
	// Create blue-green deployment
	logger.Info("Creating blue-green deployment")
	if err := createBlueGreenDeployment(rc, ghostConfig, deployCtx); err != nil {
		return fmt.Errorf("blue-green deployment failed: %w", err)
	}
	
	// Wait for health checks
	logger.Info("Waiting for deployment to be healthy")
	if err := WaitForGhostHealthy(rc, ghostConfig); err != nil {
		logger.Error("Health check failed, rolling back", zap.Error(err))
		_ = rollbackDeployment(rc, ghostConfig, deployCtx)
		return fmt.Errorf("deployment health check failed: %w", err)
	}
	
	// Promote deployment
	logger.Info("Promoting deployment")
	if err := promoteDeployment(rc, ghostConfig, deployCtx); err != nil {
		return fmt.Errorf("failed to promote deployment: %w", err)
	}
	
	// Log successful deployment
	logger.Info("Deployment completed successfully",
		zap.String("environment", environment),
		zap.String("commit", payload.After),
		zap.Duration("duration", time.Since(deployCtx.Timestamp)))
	
	// Store deployment record
	_ = storeDeploymentRecord(rc, deployCtx)

	return nil
}

// DeploymentContext holds information about a deployment
type DeploymentContext struct {
	Environment string    `json:"environment"`
	CommitID    string    `json:"commit_id"`
	CommitMsg   string    `json:"commit_msg"`
	Author      string    `json:"author"`
	Timestamp   time.Time `json:"timestamp"`
	Status      string    `json:"status"`
}

// readGhostConfig reads the current Ghost configuration
func readGhostConfig(rc *eos_io.RuntimeContext, environment string) (*GhostConfig, error) {
	// Read from Vault
	vaultPath := fmt.Sprintf("kv/data/helen/%s/config", environment)
	data, err := vaultReadSecret(rc, vaultPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config from Vault: %w", err)
	}
	
	// Reconstruct GhostConfig
	config := &GhostConfig{
		Config: &Config{
			Namespace: data["namespace"].(string),
			Port:      int(data["port"].(float64)),
			VaultAddr: data["vault_addr"].(string),
			NomadAddr: data["nomad_addr"].(string),
		},
		Mode:          "ghost",
		Domain:        data["domain"].(string),
		Environment:   environment,
		Database:      data["database"].(string),
		GitRepo:       data["git_repo"].(string),
		GitBranch:     data["git_branch"].(string),
		EnableAuth:    data["enable_auth"].(bool),
		DockerImage:   data["docker_image"].(string),
		InstanceCount: int(data["instance_count"].(float64)),
	}
	
	return config, nil
}

// updateGitRepository pulls latest changes from git
func updateGitRepository(rc *eos_io.RuntimeContext, config *GhostConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	repoPath := filepath.Join("/var/lib/helen", config.Environment, "repo")
	
	// Check if repo exists
	if _, err := os.Stat(filepath.Join(repoPath, ".git")); os.IsNotExist(err) {
		// Clone repository
		logger.Info("Cloning repository", zap.String("repo", config.GitRepo))
		cmd := exec.CommandContext(rc.Ctx, "git", "clone", "-b", config.GitBranch, config.GitRepo, repoPath)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to clone repository: %w", err)
		}
	} else {
		// Pull latest changes
		logger.Info("Pulling latest changes")
		cmd := exec.CommandContext(rc.Ctx, "git", "-C", repoPath, "pull", "origin", config.GitBranch)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to pull changes: %w", err)
		}
	}
	
	return nil
}

// createBlueGreenDeployment creates a new deployment alongside the existing one
func createBlueGreenDeployment(rc *eos_io.RuntimeContext, config *GhostConfig, ctx *DeploymentContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Modify job name for blue-green
	config.Namespace = fmt.Sprintf("%s-blue", config.Namespace)
	
	logger.Info("Creating blue deployment", zap.String("namespace", config.Namespace))
	
	// Deploy using existing DeployGhost function
	if err := DeployGhost(rc, config); err != nil {
		return fmt.Errorf("failed to create blue deployment: %w", err)
	}
	
	return nil
}

// promoteDeployment promotes the blue deployment to green
func promoteDeployment(rc *eos_io.RuntimeContext, config *GhostConfig, ctx *DeploymentContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Update Hecate route to point to new deployment
	logger.Info("Updating Hecate route")
	if err := ConfigureHecateGhostRoute(rc, config); err != nil {
		return fmt.Errorf("failed to update route: %w", err)
	}
	
	// Stop old deployment
	oldNamespace := strings.TrimSuffix(config.Namespace, "-blue")
	logger.Info("Stopping old deployment", zap.String("namespace", oldNamespace))
	
	cmd := exec.CommandContext(rc.Ctx, "nomad", "job", "stop", fmt.Sprintf("helen-ghost-%s", oldNamespace))
	if err := cmd.Run(); err != nil {
		logger.Warn("Failed to stop old deployment", zap.Error(err))
	}
	
	// Rename blue to green
	config.Namespace = oldNamespace
	
	return nil
}

// rollbackDeployment rolls back a failed deployment
func rollbackDeployment(rc *eos_io.RuntimeContext, config *GhostConfig, ctx *DeploymentContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Warn("Rolling back deployment",
		zap.String("environment", config.Environment),
		zap.String("commit", ctx.CommitID))
	
	// Stop blue deployment
	blueNamespace := fmt.Sprintf("%s-blue", config.Environment)
	cmd := exec.CommandContext(rc.Ctx, "nomad", "job", "stop", fmt.Sprintf("helen-ghost-%s", blueNamespace))
	if err := cmd.Run(); err != nil {
		logger.Error("Failed to stop blue deployment", zap.Error(err))
	}
	
	ctx.Status = "rolled_back"
	_ = storeDeploymentRecord(rc, ctx)

	return nil
}

// storeDeploymentRecord stores a deployment record in Consul
func storeDeploymentRecord(rc *eos_io.RuntimeContext, ctx *DeploymentContext) error {
	key := fmt.Sprintf("helen/deployments/%s/%d", ctx.Environment, ctx.Timestamp.Unix())
	
	data, err := json.Marshal(ctx)
	if err != nil {
		return fmt.Errorf("failed to marshal deployment record: %w", err)
	}
	
	return consulWriteKV(rc, key, string(data))
}

// CreateWebhookEndpoint creates the webhook endpoint in Hecate
func CreateWebhookEndpoint(rc *eos_io.RuntimeContext, config *GhostConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	webhookPath := fmt.Sprintf("/webhooks/helen/%s", config.Environment)
	
	logger.Info("Creating webhook endpoint",
		zap.String("path", webhookPath),
		zap.String("environment", config.Environment))
	
	// This would integrate with Hecate to create the route
	// For now, we'll document what needs to be done
	logger.Info("Webhook endpoint ready",
		zap.String("url", fmt.Sprintf("https://%s%s", config.Domain, webhookPath)))
	
	return nil
}
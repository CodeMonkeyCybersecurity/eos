package hecate

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SecretManager handles secret rotation
type SecretManager struct {
	client *HecateClient
}

// NewSecretManager creates a new secret manager
func NewSecretManager(client *HecateClient) *SecretManager {
	return &SecretManager{client: client}
}

// RotateSecretRequest represents a request to rotate a secret
type RotateSecretRequest struct {
	Name     string `json:"name"`
	Strategy string `json:"strategy"` // dual-secret, immediate
}

// RotateSecretResult represents the result of secret rotation
type RotateSecretResult struct {
	Name         string    `json:"name"`
	Strategy     string    `json:"strategy"`
	Success      bool      `json:"success"`
	NewVersion   string    `json:"new_version"`
	RotatedAt    time.Time `json:"rotated_at"`
	CleanupAfter time.Time `json:"cleanup_after,omitempty"`
	Error        string    `json:"error,omitempty"`
}

// RotateSecret rotates a single secret
func (sm *SecretManager) RotateSecret(ctx context.Context, req *RotateSecretRequest) (*RotateSecretResult, error) {
	logger := otelzap.Ctx(sm.client.rc.Ctx)
	logger.Info("Rotating secret",
		zap.String("name", req.Name),
		zap.String("strategy", req.Strategy))

	result := &RotateSecretResult{
		Name:      req.Name,
		Strategy:  req.Strategy,
		RotatedAt: time.Now(),
	}

	switch req.Strategy {
	case "dual-secret":
		err := sm.rotateDualSecret(ctx, req.Name, result)
		result.Success = err == nil
		if err != nil {
			result.Error = err.Error()
			return result, err
		}
	case "immediate":
		err := sm.rotateImmediate(ctx, req.Name, result)
		result.Success = err == nil
		if err != nil {
			result.Error = err.Error()
			return result, err
		}
	default:
		err := fmt.Errorf("unknown rotation strategy: %s", req.Strategy)
		result.Success = false
		result.Error = err.Error()
		return result, err
	}

	logger.Info("Secret rotated successfully",
		zap.String("name", req.Name),
		zap.String("strategy", req.Strategy),
		zap.String("new_version", result.NewVersion))

	return result, nil
}

// RotateAllSecrets rotates all secrets for Hecate
func (sm *SecretManager) RotateAllSecrets(ctx context.Context) ([]*RotateSecretResult, error) {
	logger := otelzap.Ctx(sm.client.rc.Ctx)
	logger.Info("Rotating all Hecate secrets")

	secrets := []struct {
		name     string
		strategy string
	}{
		{"authentik-api-token", "dual-secret"},
		{"caddy-admin-token", "dual-secret"},
		{"hetzner-api-token", "immediate"},
		{"vault-root-token", "immediate"},
		{"consul-master-token", "immediate"},
	}

	results := make([]*RotateSecretResult, 0, len(secrets))

	for _, secret := range secrets {
		req := &RotateSecretRequest{
			Name:     secret.name,
			Strategy: secret.strategy,
		}

		result, err := sm.RotateSecret(ctx, req)
		if err != nil {
			logger.Error("Failed to rotate secret",
				zap.String("name", secret.name),
				zap.Error(err))
		}
		results = append(results, result)
	}

	successCount := 0
	for _, result := range results {
		if result.Success {
			successCount++
		}
	}

	logger.Info("Bulk secret rotation completed",
		zap.Int("total", len(secrets)),
		zap.Int("successful", successCount),
		zap.Int("failed", len(secrets)-successCount))

	return results, nil
}

// GetSecretStatus gets the status of a secret
func (sm *SecretManager) GetSecretStatus(ctx context.Context, name string) (*SecretStatus, error) {
	logger := otelzap.Ctx(sm.client.rc.Ctx)
	logger.Debug("Getting secret status",
		zap.String("name", name))

	// Try to get secret from Vault
	path := fmt.Sprintf("secret/data/hecate/%s", name)
	secret, err := sm.client.vault.Logical().Read(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret: %w", err)
	}

	if secret == nil {
		return &SecretStatus{
			Name:   name,
			Exists: false,
		}, nil
	}

	status := &SecretStatus{
		Name:   name,
		Exists: true,
	}

	// Extract metadata if available
	if secret.Data != nil {
		if data, ok := secret.Data["data"].(map[string]interface{}); ok {
			if rotatedAt, ok := data["rotated_at"].(string); ok {
				if parsed, err := time.Parse(time.RFC3339, rotatedAt); err == nil {
					status.LastRotated = &parsed
				}
			}
			if version, ok := data["version"].(string); ok {
				status.Version = version
			}
		}
	}

	return status, nil
}

// ListSecrets lists all Hecate secrets
func (sm *SecretManager) ListSecrets(ctx context.Context) ([]*SecretStatus, error) {
	logger := otelzap.Ctx(sm.client.rc.Ctx)
	logger.Debug("Listing all Hecate secrets")

	secretNames := []string{
		"authentik-api-token",
		"caddy-admin-token", 
		"hetzner-api-token",
		"vault-root-token",
		"consul-master-token",
	}

	statuses := make([]*SecretStatus, 0, len(secretNames))

	for _, name := range secretNames {
		status, err := sm.GetSecretStatus(ctx, name)
		if err != nil {
			logger.Warn("Failed to get secret status",
				zap.String("name", name),
				zap.Error(err))
			status = &SecretStatus{
				Name:   name,
				Exists: false,
				Error:  err.Error(),
			}
		}
		statuses = append(statuses, status)
	}

	return statuses, nil
}

// Helper methods

func (sm *SecretManager) rotateDualSecret(ctx context.Context, name string, result *RotateSecretResult) error {
	logger := otelzap.Ctx(sm.client.rc.Ctx)
	
	// Get current secret
	currentPath := fmt.Sprintf("secret/data/hecate/%s", name)
	current, err := sm.client.vault.Logical().Read(currentPath)
	if err != nil {
		return fmt.Errorf("failed to read current secret: %w", err)
	}

	var currentValue string
	if current != nil && current.Data != nil {
		if data, ok := current.Data["data"].(map[string]interface{}); ok {
			currentValue, _ = data["value"].(string)
		}
	}

	// Generate new secret
	newValue := sm.generateSecret()
	newVersion := fmt.Sprintf("v%d", time.Now().Unix())
	result.NewVersion = newVersion

	// Store both secrets
	dualData := map[string]interface{}{
		"data": map[string]interface{}{
			"current":    newValue,
			"previous":   currentValue,
			"version":    newVersion,
			"rotated_at": time.Now().Format(time.RFC3339),
		},
	}

	_, err = sm.client.vault.Logical().Write(currentPath, dualData)
	if err != nil {
		return fmt.Errorf("failed to write dual secrets: %w", err)
	}

	// Update services to use new secret
	if err := sm.updateServices(ctx, name, newValue); err != nil {
		// Rollback
		logger.Warn("Failed to update services, rolling back secret",
			zap.String("name", name),
			zap.Error(err))
		_, rollbackErr := sm.client.vault.Logical().Write(currentPath, map[string]interface{}{
			"data": map[string]interface{}{
				"value": currentValue,
			},
		})
		_ = rollbackErr // Ignore rollback errors
		return fmt.Errorf("failed to update services: %w", err)
	}

	// Schedule cleanup of old secret
	result.CleanupAfter = time.Now().Add(1 * time.Hour)
	sm.scheduleCleanup(ctx, name, 1*time.Hour)

	return nil
}

func (sm *SecretManager) rotateImmediate(ctx context.Context, name string, result *RotateSecretResult) error {
	// Generate new secret
	newValue := sm.generateSecret()
	newVersion := fmt.Sprintf("v%d", time.Now().Unix())
	result.NewVersion = newVersion

	// Update in Vault
	path := fmt.Sprintf("secret/data/hecate/%s", name)
	_, err := sm.client.vault.Logical().Write(path, map[string]interface{}{
		"data": map[string]interface{}{
			"value":      newValue,
			"version":    newVersion,
			"rotated_at": time.Now().Format(time.RFC3339),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to write new secret: %w", err)
	}

	// Update services
	if err := sm.updateServices(ctx, name, newValue); err != nil {
		return fmt.Errorf("failed to update services: %w", err)
	}

	// Restart affected services
	if err := sm.restartServices(ctx, name); err != nil {
		return fmt.Errorf("failed to restart services: %w", err)
	}

	return nil
}

func (sm *SecretManager) generateSecret() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func (sm *SecretManager) updateServices(ctx context.Context, secretName, newValue string) error {
	logger := otelzap.Ctx(sm.client.rc.Ctx)
	logger.Info("Updating services with new secret",
		zap.String("secret_name", secretName))

	// Apply Salt state to update service configurations
	state := map[string]interface{}{
		"hecate_secret": map[string]interface{}{
			"name":  secretName,
			"value": newValue,
		},
	}

	return sm.client.salt.ApplyState(ctx, "hecate.secret_update", state)
}

func (sm *SecretManager) restartServices(ctx context.Context, secretName string) error {
	logger := otelzap.Ctx(sm.client.rc.Ctx)
	logger.Info("Restarting services for secret",
		zap.String("secret_name", secretName))

	// Determine which services use this secret
	services := sm.getAffectedServices(secretName)

	for _, service := range services {
		if err := sm.client.salt.RestartService(ctx, service); err != nil {
			return fmt.Errorf("failed to restart %s: %w", service, err)
		}
	}

	return nil
}

func (sm *SecretManager) scheduleCleanup(ctx context.Context, name string, after time.Duration) {
	logger := otelzap.Ctx(sm.client.rc.Ctx)
	logger.Info("Scheduling secret cleanup",
		zap.String("name", name),
		zap.Duration("after", after))

	// Store cleanup task in Consul
	cleanupTime := time.Now().Add(after)
	data := []byte(fmt.Sprintf(`{"secret_name":"%s","cleanup_time":"%s","created_at":"%s"}`, 
		name, cleanupTime.Format(time.RFC3339), time.Now().Format(time.RFC3339)))
	key := fmt.Sprintf("hecate/secret-cleanup/%s-%d", name, cleanupTime.Unix())
	sm.client.consul.KV().Put(&api.KVPair{
		Key:   key,
		Value: data,
	}, nil)
}

func (sm *SecretManager) getAffectedServices(secretName string) []string {
	// Map secret names to services that use them
	serviceMap := map[string][]string{
		"authentik-api-token": {"authentik"},
		"caddy-admin-token":   {"caddy"},
		"hetzner-api-token":   {"hecate-api"},
		"vault-root-token":    {"vault"},
		"consul-master-token": {"consul"},
	}

	services, exists := serviceMap[secretName]
	if !exists {
		return []string{}
	}
	return services
}

// SecretStatus represents the status of a secret
type SecretStatus struct {
	Name        string     `json:"name"`
	Exists      bool       `json:"exists"`
	Version     string     `json:"version,omitempty"`
	LastRotated *time.Time `json:"last_rotated,omitempty"`
	Error       string     `json:"error,omitempty"`
}
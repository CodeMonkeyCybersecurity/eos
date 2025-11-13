// pkg/hecate/state_manager.go
//
// Hecate state management using Consul KV SDK.
// Migrated from shell commands to SDK calls for improved reliability.
//
// Last Updated: 2025-01-25

package hecate

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/sdk"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	consulapi "github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

const (
	// ConsulKVPrefix is the base path for Hecate state in Consul
	ConsulKVPrefix = "hecate/"
)

// StateManager handles persistent state for Hecate configuration
type StateManager struct {
	prefix string
	rc     *eos_io.RuntimeContext
	client *consulapi.Client
}

// NewStateManager creates a new state manager instance with Consul SDK client
func NewStateManager(rc *eos_io.RuntimeContext) (*StateManager, error) {
	// Create Consul SDK client
	client, err := sdk.NewClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w", err)
	}

	return &StateManager{
		prefix: ConsulKVPrefix,
		rc:     rc,
		client: client,
	}, nil
}

// SaveRoute stores a route configuration in Consul
func (sm *StateManager) SaveRoute(rc *eos_io.RuntimeContext, route *Route) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Saving route to state store",
		zap.String("route_id", route.ID),
		zap.String("domain", route.Domain))

	// Serialize route to JSON
	data, err := json.Marshal(route)
	if err != nil {
		return fmt.Errorf("failed to marshal route: %w", err)
	}

	// Store in Consul KV using SDK
	key := path.Join(sm.prefix, "routes", route.ID)
	if err := sdk.KVPut(rc.Ctx, sm.client, key, data); err != nil {
		return fmt.Errorf("failed to store route in Consul: %w", err)
	}

	logger.Debug("Route saved to Consul", zap.String("key", key))

	// Also store domain mapping for quick lookups
	domainKey := path.Join(sm.prefix, "domains", route.Domain)
	if err := sdk.KVPut(rc.Ctx, sm.client, domainKey, []byte(route.ID)); err != nil {
		// Try to rollback the route storage
		_ = sdk.KVDelete(rc.Ctx, sm.client, key)
		return fmt.Errorf("failed to store domain mapping: %w", err)
	}

	return nil
}

// GetRoute retrieves a route configuration from Consul
func (sm *StateManager) GetRoute(rc *eos_io.RuntimeContext, routeID string) (*Route, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Retrieving route from state store",
		zap.String("route_id", routeID))

	key := path.Join(sm.prefix, "routes", routeID)
	data, err := sdk.KVGet(rc.Ctx, sm.client, key)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve route from Consul: %w", err)
	}

	if data == nil {
		return nil, fmt.Errorf("route not found: %s", routeID)
	}

	var route Route
	if err := json.Unmarshal(data, &route); err != nil {
		return nil, fmt.Errorf("failed to unmarshal route: %w", err)
	}

	return &route, nil
}

// GetRouteByDomain retrieves a route by its domain
func (sm *StateManager) GetRouteByDomain(rc *eos_io.RuntimeContext, domain string) (*Route, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Looking up route by domain",
		zap.String("domain", domain))

	// First get the route ID from domain mapping
	domainKey := path.Join(sm.prefix, "domains", domain)
	data, err := sdk.KVGet(rc.Ctx, sm.client, domainKey)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup domain: %w", err)
	}

	if data == nil {
		return nil, fmt.Errorf("no route found for domain: %s", domain)
	}

	routeID := strings.TrimSpace(string(data))
	return sm.GetRoute(rc, routeID)
}

// ListRoutes retrieves all routes from Consul
func (sm *StateManager) ListRoutes(rc *eos_io.RuntimeContext) ([]*Route, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Listing all routes from state store")

	// List all route keys
	prefix := path.Join(sm.prefix, "routes/")
	keys, err := sdk.KVList(rc.Ctx, sm.client, prefix)
	if err != nil {
		return nil, fmt.Errorf("failed to list routes: %w", err)
	}

	if len(keys) == 0 {
		return []*Route{}, nil
	}

	// Parse route IDs from keys
	var routes []*Route

	for _, key := range keys {
		if key == "" {
			continue
		}

		// Extract route ID from key
		routeID := strings.TrimPrefix(key, prefix)
		if routeID == "" {
			continue
		}

		// Retrieve the route
		route, err := sm.GetRoute(rc, routeID)
		if err != nil {
			logger.Warn("Failed to retrieve route",
				zap.String("route_id", routeID),
				zap.Error(err))
			continue
		}

		routes = append(routes, route)
	}

	logger.Info("Retrieved routes from state store",
		zap.Int("count", len(routes)))

	return routes, nil
}

// DeleteRoute removes a route from Consul
func (sm *StateManager) DeleteRoute(rc *eos_io.RuntimeContext, routeID string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Deleting route from state store",
		zap.String("route_id", routeID))

	// First get the route to find the hostname
	route, err := sm.GetRoute(rc, routeID)
	if err != nil {
		return err
	}

	// Delete the route data
	key := path.Join(sm.prefix, "routes", routeID)
	if err := sdk.KVDelete(rc.Ctx, sm.client, key); err != nil {
		return fmt.Errorf("failed to delete route: %w", err)
	}

	// Delete the domain mapping
	domainKey := path.Join(sm.prefix, "domains", route.Domain)
	if err := sdk.KVDelete(rc.Ctx, sm.client, domainKey); err != nil {
		logger.Warn("Failed to delete domain mapping",
			zap.String("domain", route.Domain),
			zap.Error(err))
	}

	logger.Debug("Route deleted from Consul")

	return nil
}

// SaveAuthPolicy stores an authentication policy in Consul
func (sm *StateManager) SaveAuthPolicy(rc *eos_io.RuntimeContext, policy *AuthPolicy) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Saving auth policy to state store",
		zap.String("policy_name", policy.Name))

	// Serialize policy to JSON
	data, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}

	// Store in Consul KV using SDK
	key := path.Join(sm.prefix, "auth_policies", policy.Name)
	if err := sdk.KVPut(rc.Ctx, sm.client, key, data); err != nil {
		return fmt.Errorf("failed to store policy in Consul: %w", err)
	}

	logger.Debug("Auth policy saved to Consul", zap.String("key", key))

	return nil
}

// GetAuthPolicy retrieves an authentication policy from Consul
func (sm *StateManager) GetAuthPolicy(rc *eos_io.RuntimeContext, policyName string) (*AuthPolicy, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Retrieving auth policy from state store",
		zap.String("policy_name", policyName))

	key := path.Join(sm.prefix, "auth_policies", policyName)
	data, err := sdk.KVGet(rc.Ctx, sm.client, key)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve policy from Consul: %w", err)
	}

	if data == nil {
		return nil, fmt.Errorf("auth policy not found: %s", policyName)
	}

	var policy AuthPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy: %w", err)
	}

	return &policy, nil
}

// ListAuthPolicies retrieves all authentication policies from Consul
func (sm *StateManager) ListAuthPolicies(rc *eos_io.RuntimeContext) ([]*AuthPolicy, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Listing all auth policies from state store")

	// List all policy keys
	prefix := path.Join(sm.prefix, "auth_policies/")
	keys, err := sdk.KVList(rc.Ctx, sm.client, prefix)
	if err != nil {
		return nil, fmt.Errorf("failed to list policies: %w", err)
	}

	if len(keys) == 0 {
		return []*AuthPolicy{}, nil
	}

	// Parse policy names from keys
	var policies []*AuthPolicy

	for _, key := range keys {
		if key == "" {
			continue
		}

		// Extract policy name from key
		policyName := strings.TrimPrefix(key, prefix)
		if policyName == "" {
			continue
		}

		// Retrieve the policy
		policy, err := sm.GetAuthPolicy(rc, policyName)
		if err != nil {
			logger.Warn("Failed to retrieve policy",
				zap.String("policy_name", policyName),
				zap.Error(err))
			continue
		}

		policies = append(policies, policy)
	}

	logger.Info("Retrieved auth policies from state store",
		zap.Int("count", len(policies)))

	return policies, nil
}

// DeleteAuthPolicy removes an authentication policy from Consul
func (sm *StateManager) DeleteAuthPolicy(rc *eos_io.RuntimeContext, policyName string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Deleting auth policy from state store",
		zap.String("policy_name", policyName))

	key := path.Join(sm.prefix, "auth_policies", policyName)
	if err := sdk.KVDelete(rc.Ctx, sm.client, key); err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}

	logger.Debug("Auth policy deleted from Consul")

	return nil
}

// SaveDeploymentConfig stores the deployment configuration in Consul
func (sm *StateManager) SaveDeploymentConfig(rc *eos_io.RuntimeContext, config *HecateDeploymentConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Saving deployment config to state store")

	// Serialize config to JSON
	data, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Store in Consul KV using SDK
	key := path.Join(sm.prefix, "config", "deployment")
	if err := sdk.KVPut(rc.Ctx, sm.client, key, data); err != nil {
		return fmt.Errorf("failed to store config in Consul: %w", err)
	}

	logger.Debug("Deployment config saved to Consul", zap.String("key", key))

	return nil
}

// GetDeploymentConfig retrieves the deployment configuration from Consul
func (sm *StateManager) GetDeploymentConfig(rc *eos_io.RuntimeContext) (*HecateDeploymentConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Retrieving deployment config from state store")

	key := path.Join(sm.prefix, "config", "deployment")
	data, err := sdk.KVGet(rc.Ctx, sm.client, key)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve config from Consul: %w", err)
	}

	if data == nil {
		return nil, fmt.Errorf("deployment config not found")
	}

	var config HecateDeploymentConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &config, nil
}

// BackupState creates a backup of all Hecate state in Consul
func (sm *StateManager) BackupState(rc *eos_io.RuntimeContext, backupPath string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating state backup",
		zap.String("backup_path", backupPath))

	// Export all Hecate keys from Consul using SDK
	data, err := sdk.KVExport(rc.Ctx, sm.client, sm.prefix)
	if err != nil {
		return fmt.Errorf("failed to export state: %w", err)
	}

	// Convert to JSON for backup file
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal backup data: %w", err)
	}

	// Write to backup file
	if err := os.WriteFile(backupPath, jsonData, shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("failed to write backup: %w", err)
	}

	logger.Info("State backup created successfully",
		zap.String("backup_path", backupPath),
		zap.Int("keys_backed_up", len(data)))

	return nil
}

// RestoreState restores Hecate state from a backup
func (sm *StateManager) RestoreState(rc *eos_io.RuntimeContext, backupPath string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Restoring state from backup",
		zap.String("backup_path", backupPath))

	// Read backup file
	jsonData, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup: %w", err)
	}

	// Parse JSON backup data
	var data map[string][]byte
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return fmt.Errorf("failed to unmarshal backup: %w", err)
	}

	// Import into Consul using SDK
	if err := sdk.KVImport(rc.Ctx, sm.client, data); err != nil {
		return fmt.Errorf("failed to import state: %w", err)
	}

	logger.Info("State restored successfully",
		zap.Int("keys_restored", len(data)))

	return nil
}

// Helper functions for the existing auth.go

func updateStateStore(rc *eos_io.RuntimeContext, storeType, key string, value interface{}) error {
	sm, err := NewStateManager(rc)
	if err != nil {
		return fmt.Errorf("failed to create state manager: %w", err)
	}

	switch storeType {
	case "auth_policies":
		if policy, ok := value.(*AuthPolicy); ok {
			return sm.SaveAuthPolicy(rc, policy)
		}
	case "routes":
		if route, ok := value.(*Route); ok {
			return sm.SaveRoute(rc, route)
		}
	}

	return fmt.Errorf("unsupported store type: %s", storeType)
}

func deleteFromStateStore(rc *eos_io.RuntimeContext, storeType, key string) error {
	sm, err := NewStateManager(rc)
	if err != nil {
		return fmt.Errorf("failed to create state manager: %w", err)
	}

	switch storeType {
	case "auth_policies":
		return sm.DeleteAuthPolicy(rc, key)
	case "routes":
		return sm.DeleteRoute(rc, key)
	}

	return fmt.Errorf("unsupported store type: %s", storeType)
}

// UpdatePhase updates the deployment phase status in Consul
func (sm *StateManager) UpdatePhase(phase, status string) error {
	logger := otelzap.Ctx(sm.rc.Ctx)
	logger.Debug("Updating deployment phase status",
		zap.String("phase", phase),
		zap.String("status", status))

	key := path.Join(sm.prefix, "deployment", "phases", phase)
	if err := sdk.KVPut(sm.rc.Ctx, sm.client, key, []byte(status)); err != nil {
		return fmt.Errorf("failed to update phase status: %w", err)
	}

	logger.Debug("Phase status updated", zap.String("key", key))

	return nil
}

// SetDeploymentComplete marks the deployment as complete in Consul
func (sm *StateManager) SetDeploymentComplete() error {
	logger := otelzap.Ctx(sm.rc.Ctx)
	logger.Info("Marking deployment as complete")

	// Update deployment status
	statusKey := path.Join(sm.prefix, "deployment", "status")
	if err := sdk.KVPut(sm.rc.Ctx, sm.client, statusKey, []byte("complete")); err != nil {
		return fmt.Errorf("failed to update deployment status: %w", err)
	}

	// Update deployment timestamp
	timestampKey := path.Join(sm.prefix, "deployment", "completed_at")
	timestampValue := fmt.Sprintf("%d", time.Now().Unix())
	if err := sdk.KVPut(sm.rc.Ctx, sm.client, timestampKey, []byte(timestampValue)); err != nil {
		logger.Warn("Failed to update completion timestamp", zap.Error(err))
	}

	logger.Debug("Deployment marked as complete")

	return nil
}

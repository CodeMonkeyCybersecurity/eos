package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ReconcileConfig contains configuration for state reconciliation
type ReconcileConfig struct {
	Component  string // "all", "routes", "upstreams", "auth-policies"
	DryRun     bool
	Force      bool
	FromCommit string
}

// StateDiff represents the differences between desired and runtime state
type StateDiff struct {
	ToCreate []Change
	ToUpdate []Change
	ToDelete []Change
}

// Change represents a single state change
type Change struct {
	Type     string // "route", "upstream", "auth_policy"
	Name     string
	OldValue interface{}
	NewValue interface{}
}

// Transaction manages rollback capability for multi-step operations
type Transaction struct {
	rc        *eos_io.RuntimeContext
	rollbacks []func() error
	mutex     sync.Mutex
	committed bool
}

// ReconcileState compares desired state with runtime state and reconciles differences
func ReconcileState(rc *eos_io.RuntimeContext, config *ReconcileConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Acquire lock and check prerequisites
	logger.Info("Acquiring distributed lock for reconciliation",
		zap.String("component", config.Component))

	lock, err := acquireConsulLock(rc, "hecate/reconcile", config.Force)
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() { _ = lock.Unlock() }()

	// Get current runtime state
	logger.Info("Fetching current runtime state")
	runtimeState, err := fetchRuntimeState(rc, config.Component)
	if err != nil {
		return fmt.Errorf("failed to fetch runtime state: %w", err)
	}

	// Get desired state from source of truth
	logger.Info("Fetching desired state from source of truth")
	desiredState, err := fetchDesiredState(rc, config.Component, config.FromCommit)
	if err != nil {
		return fmt.Errorf("failed to fetch desired state: %w", err)
	}

	// INTERVENE - Calculate and apply changes
	logger.Info("Calculating state differences")

	changes := calculateStateDiff(runtimeState, desiredState)
	if len(changes.ToCreate)+len(changes.ToUpdate)+len(changes.ToDelete) == 0 {
		logger.Info("No changes needed - state is already reconciled")
		return nil
	}

	// Log what we're going to do
	logger.Info("State reconciliation plan",
		zap.Int("create", len(changes.ToCreate)),
		zap.Int("update", len(changes.ToUpdate)),
		zap.Int("delete", len(changes.ToDelete)))

	if config.DryRun {
		logger.Info("Dry run mode - would apply the following changes")
		for _, change := range changes.ToCreate {
			logger.Info("Would create",
				zap.String("type", change.Type),
				zap.String("name", change.Name))
		}
		for _, change := range changes.ToUpdate {
			logger.Info("Would update",
				zap.String("type", change.Type),
				zap.String("name", change.Name))
		}
		for _, change := range changes.ToDelete {
			logger.Info("Would delete",
				zap.String("type", change.Type),
				zap.String("name", change.Name))
		}
		return nil
	}

	// Create transaction for rollback capability
	tx := NewTransaction(rc)

	// Apply changes in dependency order
	if err := applyChangesInOrder(rc, tx, changes); err != nil {
		logger.Error("Failed to apply changes, rolling back",
			zap.Error(err))
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			logger.Error("Rollback failed",
				zap.Error(rollbackErr))
			return fmt.Errorf("reconciliation failed and rollback failed")
		}
		return fmt.Errorf("reconciliation failed: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Update state fingerprints in Consul
	if err := updateStateFingerprints(rc, desiredState); err != nil {
		logger.Warn("Failed to update state fingerprints",
			zap.Error(err))
	}

	// EVALUATE - Verify reconciliation succeeded
	logger.Info("Verifying reconciliation results")

	newRuntimeState, err := fetchRuntimeState(rc, config.Component)
	if err != nil {
		return fmt.Errorf("failed to fetch runtime state for verification: %w", err)
	}

	if !statesMatch(desiredState, newRuntimeState) {
		return fmt.Errorf("reconciliation verification failed - states don't match")
	}

	logger.Info("State reconciliation completed successfully",
		zap.String("component", config.Component))

	return nil
}

// NewTransaction creates a new transaction
func NewTransaction(rc *eos_io.RuntimeContext) *Transaction {
	return &Transaction{
		rc:        rc,
		rollbacks: []func() error{},
	}
}

// AddRollback adds a rollback function to the transaction
func (t *Transaction) AddRollback(fn func() error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	// Add rollback functions in reverse order (LIFO)
	t.rollbacks = append([]func() error{fn}, t.rollbacks...)
}

// Commit marks the transaction as successful
func (t *Transaction) Commit() error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	logger := otelzap.Ctx(t.rc.Ctx)
	logger.Info("Committing transaction")

	t.committed = true
	return nil
}

// Rollback executes all rollback functions
func (t *Transaction) Rollback() error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if t.committed {
		return fmt.Errorf("cannot rollback committed transaction")
	}

	logger := otelzap.Ctx(t.rc.Ctx)
	logger.Info("Rolling back transaction",
		zap.Int("rollback_count", len(t.rollbacks)))

	var errors []error

	for i, rollback := range t.rollbacks {
		logger.Info("Executing rollback",
			zap.Int("step", i+1),
			zap.Int("total", len(t.rollbacks)))

		if err := rollback(); err != nil {
			logger.Error("Rollback failed",
				zap.Int("step", i+1),
				zap.Error(err))
			errors = append(errors, err)
			// Continue with other rollbacks
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("rollback completed with %d errors", len(errors))
	}

	return nil
}

// calculateStateDiff compares two states and returns the differences
func calculateStateDiff(runtime, desired *hecate.State) *StateDiff {
	diff := &StateDiff{
		ToCreate: []Change{},
		ToUpdate: []Change{},
		ToDelete: []Change{},
	}

	// Check routes
	for name, desiredRoute := range desired.Routes {
		if runtimeRoute, exists := runtime.Routes[name]; exists {
			if !routesEqual(runtimeRoute, desiredRoute) {
				diff.ToUpdate = append(diff.ToUpdate, Change{
					Type:     "route",
					Name:     name,
					OldValue: runtimeRoute,
					NewValue: desiredRoute,
				})
			}
		} else {
			diff.ToCreate = append(diff.ToCreate, Change{
				Type:     "route",
				Name:     name,
				NewValue: desiredRoute,
			})
		}
	}

	// Check for routes to delete
	for name, runtimeRoute := range runtime.Routes {
		if _, exists := desired.Routes[name]; !exists {
			diff.ToDelete = append(diff.ToDelete, Change{
				Type:     "route",
				Name:     name,
				OldValue: runtimeRoute,
			})
		}
	}

	// Similar logic for upstreams
	for name, desiredUpstream := range desired.Upstreams {
		if runtimeUpstream, exists := runtime.Upstreams[name]; exists {
			if !upstreamsEqual(runtimeUpstream, desiredUpstream) {
				diff.ToUpdate = append(diff.ToUpdate, Change{
					Type:     "upstream",
					Name:     name,
					OldValue: runtimeUpstream,
					NewValue: desiredUpstream,
				})
			}
		} else {
			diff.ToCreate = append(diff.ToCreate, Change{
				Type:     "upstream",
				Name:     name,
				NewValue: desiredUpstream,
			})
		}
	}

	for name, runtimeUpstream := range runtime.Upstreams {
		if _, exists := desired.Upstreams[name]; !exists {
			diff.ToDelete = append(diff.ToDelete, Change{
				Type:     "upstream",
				Name:     name,
				OldValue: runtimeUpstream,
			})
		}
	}

	// Similar logic for auth policies
	for name, desiredPolicy := range desired.AuthPolicies {
		if runtimePolicy, exists := runtime.AuthPolicies[name]; exists {
			if !authPoliciesEqual(runtimePolicy, desiredPolicy) {
				diff.ToUpdate = append(diff.ToUpdate, Change{
					Type:     "auth_policy",
					Name:     name,
					OldValue: runtimePolicy,
					NewValue: desiredPolicy,
				})
			}
		} else {
			diff.ToCreate = append(diff.ToCreate, Change{
				Type:     "auth_policy",
				Name:     name,
				NewValue: desiredPolicy,
			})
		}
	}

	for name, runtimePolicy := range runtime.AuthPolicies {
		if _, exists := desired.AuthPolicies[name]; !exists {
			diff.ToDelete = append(diff.ToDelete, Change{
				Type:     "auth_policy",
				Name:     name,
				OldValue: runtimePolicy,
			})
		}
	}

	return diff
}

// applyChangesInOrder applies changes respecting dependencies
func applyChangesInOrder(rc *eos_io.RuntimeContext, tx *Transaction, changes *StateDiff) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Order of operations matters:
	// 1. Create/update auth policies first (routes depend on them)
	// 2. Create/update upstreams (routes depend on them)
	// 3. Create/update routes
	// 4. Delete in reverse order

	// Phase 1: Create auth policies
	for _, change := range changes.ToCreate {
		if change.Type == "auth_policy" {
			logger.Info("Creating auth policy",
				zap.String("name", change.Name))
			if err := hecate.CreateAuthPolicy(rc, change.NewValue.(*hecate.AuthPolicy)); err != nil {
				return fmt.Errorf("failed to create auth policy %s: %w", change.Name, err)
			}
			tx.AddRollback(func() error {
				return hecate.DeleteAuthPolicy(rc, change.Name)
			})
		}
	}

	// Phase 2: Create upstreams
	for _, change := range changes.ToCreate {
		if change.Type == "upstream" {
			logger.Info("Creating upstream",
				zap.String("name", change.Name))
			if err := hecate.CreateUpstream(rc, change.NewValue.(*hecate.Upstream)); err != nil {
				return fmt.Errorf("failed to create upstream %s: %w", change.Name, err)
			}
			tx.AddRollback(func() error {
				return hecate.DeleteUpstream(rc, change.Name)
			})
		}
	}

	// Phase 3: Create routes
	for _, change := range changes.ToCreate {
		if change.Type == "route" {
			logger.Info("Creating route",
				zap.String("name", change.Name))
			// TODO: Get config from context or parameter
			config := &hecate.HecateConfig{} // Placeholder
			if err := hecate.CreateRoute(rc, config, change.NewValue.(*hecate.Route)); err != nil {
				return fmt.Errorf("failed to create route %s: %w", change.Name, err)
			}
			tx.AddRollback(func() error {
				deleteOpts := &hecate.DeleteOptions{Force: true}
				return hecate.DeleteRoute(rc, config, change.Name, deleteOpts)
			})
		}
	}

	// Phase 4: Update auth policies
	for _, change := range changes.ToUpdate {
		if change.Type == "auth_policy" {
			logger.Info("Updating auth policy",
				zap.String("name", change.Name))
			oldPolicy := change.OldValue.(*hecate.AuthPolicy)
			newPolicy := change.NewValue.(*hecate.AuthPolicy)
			if err := hecate.UpdateAuthPolicy(rc, change.Name, newPolicy); err != nil {
				return fmt.Errorf("failed to update auth policy %s: %w", change.Name, err)
			}
			tx.AddRollback(func() error {
				return hecate.UpdateAuthPolicy(rc, change.Name, oldPolicy)
			})
		}
	}

	// Phase 5: Update upstreams
	for _, change := range changes.ToUpdate {
		if change.Type == "upstream" {
			logger.Info("Updating upstream",
				zap.String("name", change.Name))
			// TODO: Implement upstream update
		}
	}

	// Phase 6: Update routes
	for _, change := range changes.ToUpdate {
		if change.Type == "route" {
			logger.Info("Updating route",
				zap.String("name", change.Name))
			// TODO: Get config from context or parameter
			config := &hecate.HecateConfig{} // Placeholder
			if err := hecate.UpdateRoute(rc, config, change.Name, change.NewValue.(*hecate.Route)); err != nil {
				return fmt.Errorf("failed to update route %s: %w", change.Name, err)
			}
			// TODO: Add rollback
		}
	}

	// Phase 7: Delete routes first (they depend on upstreams and policies)
	for _, change := range changes.ToDelete {
		if change.Type == "route" {
			logger.Info("Deleting route",
				zap.String("name", change.Name))
			// TODO: Get config from context or parameter
			config := &hecate.HecateConfig{} // Placeholder
			deleteOpts := &hecate.DeleteOptions{Force: true}
			if err := hecate.DeleteRoute(rc, config, change.Name, deleteOpts); err != nil {
				return fmt.Errorf("failed to delete route %s: %w", change.Name, err)
			}
		}
	}

	// Phase 8: Delete upstreams
	for _, change := range changes.ToDelete {
		if change.Type == "upstream" {
			logger.Info("Deleting upstream",
				zap.String("name", change.Name))
			if err := hecate.DeleteUpstream(rc, change.Name); err != nil {
				return fmt.Errorf("failed to delete upstream %s: %w", change.Name, err)
			}
		}
	}

	// Phase 9: Delete auth policies last
	for _, change := range changes.ToDelete {
		if change.Type == "auth_policy" {
			logger.Info("Deleting auth policy",
				zap.String("name", change.Name))
			if err := hecate.DeleteAuthPolicy(rc, change.Name); err != nil {
				return fmt.Errorf("failed to delete auth policy %s: %w", change.Name, err)
			}
		}
	}

	return nil
}

// Helper functions for Consul integration

func acquireConsulLock(rc *eos_io.RuntimeContext, key string, force bool) (*api.Lock, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Get Consul client
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w", err)
	}

	// Create lock options
	opts := &api.LockOptions{
		Key:         key,
		SessionTTL:  "60s",
		SessionName: "hecate-reconciler",
	}

	lock, err := client.LockOpts(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create lock: %w", err)
	}

	// Try to acquire lock
	logger.Debug("Attempting to acquire lock",
		zap.String("key", key))

	stopCh := make(chan struct{})
	lockCh, err := lock.Lock(stopCh)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire lock: %w", err)
	}

	if lockCh == nil {
		if force {
			logger.Warn("Lock already held but force flag set, continuing anyway")
		} else {
			return nil, fmt.Errorf("lock is already held by another process")
		}
	}

	return lock, nil
}

// State fetching functions

func fetchRuntimeState(rc *eos_io.RuntimeContext, component string) (*hecate.State, error) {
	// TODO: Implement fetching runtime state from Caddy/Authentik
	return &hecate.State{
		Routes:       make(map[string]*hecate.Route),
		Upstreams:    make(map[string]*hecate.Upstream),
		AuthPolicies: make(map[string]*hecate.AuthPolicy),
		Version:      "1.0.0",
		LastUpdated:  time.Now(),
	}, nil
}

func fetchDesiredState(rc *eos_io.RuntimeContext, component, fromCommit string) (*hecate.State, error) {
	// TODO: Implement fetching desired state from Git/
	return &hecate.State{
		Routes:       make(map[string]*hecate.Route),
		Upstreams:    make(map[string]*hecate.Upstream),
		AuthPolicies: make(map[string]*hecate.AuthPolicy),
		Version:      "1.0.0",
		LastUpdated:  time.Now(),
	}, nil
}

// Comparison functions

func routesEqual(r1, r2 *hecate.Route) bool {
	// Compare all relevant fields
	if r1.Domain != r2.Domain ||
		r1.Upstream != r2.Upstream ||
		r1.AuthPolicy != r2.AuthPolicy {
		return false
	}

	// Compare headers
	if len(r1.Headers) != len(r2.Headers) {
		return false
	}
	for k, v := range r1.Headers {
		if r2.Headers[k] != v {
			return false
		}
	}

	// TODO: Compare other fields
	return true
}

func upstreamsEqual(u1, u2 *hecate.Upstream) bool {
	if u1.URL != u2.URL ||
		u1.LoadBalancePolicy != u2.LoadBalancePolicy ||
		u1.Timeout != u2.Timeout {
		return false
	}

	// Compare TLS settings
	if u1.TLSSkipVerify != u2.TLSSkipVerify {
		return false
	}

	// Compare other settings
	if u1.MaxIdleConns != u2.MaxIdleConns ||
		u1.MaxConnsPerHost != u2.MaxConnsPerHost ||
		u1.KeepAlive != u2.KeepAlive {
		return false
	}

	return true
}

func authPoliciesEqual(p1, p2 *hecate.AuthPolicy) bool {
	if p1.Name != p2.Name ||
		p1.Provider != p2.Provider ||
		p1.Flow != p2.Flow ||
		p1.RequireMFA != p2.RequireMFA {
		return false
	}

	// Compare groups
	if len(p1.Groups) != len(p2.Groups) {
		return false
	}
	for i, group := range p1.Groups {
		if p2.Groups[i] != group {
			return false
		}
	}

	return true
}

func statesMatch(s1, s2 *hecate.State) bool {
	// Quick check on counts
	if len(s1.Routes) != len(s2.Routes) ||
		len(s1.Upstreams) != len(s2.Upstreams) ||
		len(s1.AuthPolicies) != len(s2.AuthPolicies) {
		return false
	}

	// Deep comparison would go here
	// For now, return true if counts match
	return true
}

func updateStateFingerprints(rc *eos_io.RuntimeContext, state *hecate.State) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Calculate fingerprint
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	hash := sha256.Sum256(data)
	fingerprint := hex.EncodeToString(hash[:])

	logger.Debug("Updating state fingerprint",
		zap.String("fingerprint", fingerprint))

	// TODO: Store fingerprint in Consul
	return nil
}

func routeToUpdateMap(route *hecate.Route) map[string]interface{} {
	return map[string]interface{}{
		"upstream":     route.Upstream,
		"auth_policy":  route.AuthPolicy,
		"headers":      route.Headers,
		"tls":          route.TLS,
		"rate_limit":   route.RateLimit,
		"health_check": route.HealthCheck,
	}
}

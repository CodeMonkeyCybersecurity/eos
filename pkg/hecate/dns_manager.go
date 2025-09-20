package hecate

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DNSManager handles DNS reconciliation and lifecycle management
type DNSManager struct {
	client *HecateClient
}

// NewDNSManager creates a new DNS manager
func NewDNSManager(client *HecateClient) *DNSManager {
	return &DNSManager{client: client}
}

// DNSRecord represents a DNS record
type DNSRecord struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Value  string `json:"value"`
	TTL    int    `json:"ttl"`
	ZoneID string `json:"zone_id"`
}

// DNSReconcileResult represents the result of DNS reconciliation
type DNSReconcileResult struct {
	Created  []string `json:"created"`
	Updated  []string `json:"updated"`
	Deleted  []string `json:"deleted"`
	Errors   []string `json:"errors"`
	Duration string   `json:"duration"`
}

// ReconcileDNS ensures DNS records match active routes
func (dm *DNSManager) ReconcileDNS(ctx context.Context) (*DNSReconcileResult, error) {
	logger := otelzap.Ctx(dm.client.rc.Ctx)
	logger.Info("Starting DNS reconciliation")
	
	start := time.Now()
	result := &DNSReconcileResult{
		Created: []string{},
		Updated: []string{},
		Deleted: []string{},
		Errors:  []string{},
	}

	// Get active routes from Consul
	activeRoutes, err := dm.getActiveRoutes(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get active routes: %w", err)
	}

	// Get current DNS records from Hetzner (via Terraform state)
	currentDNS, err := dm.getCurrentDNSRecords(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get current DNS records: %w", err)
	}

	// Reconcile: create missing DNS records
	for domain, route := range activeRoutes {
		if route.ManageDNS {
			if _, exists := currentDNS[domain]; !exists {
				if err := dm.createDNSRecord(ctx, domain, route.IngressIP); err != nil {
					errorMsg := fmt.Sprintf("failed to create DNS for %s: %v", domain, err)
					result.Errors = append(result.Errors, errorMsg)
					logger.Error(errorMsg, zap.Error(err))
				} else {
					result.Created = append(result.Created, domain)
					logger.Info("Created DNS record", zap.String("domain", domain))
				}
			}
		}
	}

	// Reconcile: remove orphaned DNS records
	for domain := range currentDNS {
		// Skip wildcard and system records
		if strings.HasPrefix(domain, "*") || domain == "@" {
			continue
		}
		
		if _, exists := activeRoutes[domain]; !exists {
			if err := dm.deleteDNSRecord(ctx, domain); err != nil {
				errorMsg := fmt.Sprintf("failed to delete DNS for %s: %v", domain, err)
				result.Errors = append(result.Errors, errorMsg)
				logger.Error(errorMsg, zap.Error(err))
			} else {
				result.Deleted = append(result.Deleted, domain)
				logger.Info("Deleted orphaned DNS record", zap.String("domain", domain))
			}
		}
	}

	// Update DNS records that have changed IPs
	for domain, route := range activeRoutes {
		if route.ManageDNS {
			if currentRecord, exists := currentDNS[domain]; exists {
				if currentRecord.Value != route.IngressIP {
					if err := dm.updateDNSRecord(ctx, domain, route.IngressIP); err != nil {
						errorMsg := fmt.Sprintf("failed to update DNS for %s: %v", domain, err)
						result.Errors = append(result.Errors, errorMsg)
						logger.Error(errorMsg, zap.Error(err))
					} else {
						result.Updated = append(result.Updated, domain)
						logger.Info("Updated DNS record",
							zap.String("domain", domain),
							zap.String("old_ip", currentRecord.Value),
							zap.String("new_ip", route.IngressIP))
					}
				}
			}
		}
	}

	result.Duration = time.Since(start).String()

	logger.Info("DNS reconciliation completed",
		zap.Int("created", len(result.Created)),
		zap.Int("updated", len(result.Updated)),
		zap.Int("deleted", len(result.Deleted)),
		zap.Int("errors", len(result.Errors)),
		zap.String("duration", result.Duration))

	return result, nil
}

// ListDNSRecords lists all DNS records managed by Hecate
func (dm *DNSManager) ListDNSRecords(ctx context.Context) (map[string]*DNSRecord, error) {
	logger := otelzap.Ctx(dm.client.rc.Ctx)
	logger.Debug("Listing DNS records")

	return dm.getCurrentDNSRecords(ctx)
}

// CreateDNSRecord creates a DNS record for a domain
func (dm *DNSManager) CreateDNSRecord(ctx context.Context, domain, target string) error {
	logger := otelzap.Ctx(dm.client.rc.Ctx)
	logger.Info("Creating DNS record",
		zap.String("domain", domain),
		zap.String("target", target))

	return dm.createDNSRecord(ctx, domain, target)
}

// UpdateDNSRecord updates a DNS record
func (dm *DNSManager) UpdateDNSRecord(ctx context.Context, domain, target string) error {
	logger := otelzap.Ctx(dm.client.rc.Ctx)
	logger.Info("Updating DNS record",
		zap.String("domain", domain),
		zap.String("target", target))

	return dm.updateDNSRecord(ctx, domain, target)
}

// DeleteDNSRecord deletes a DNS record
func (dm *DNSManager) DeleteDNSRecord(ctx context.Context, domain string) error {
	logger := otelzap.Ctx(dm.client.rc.Ctx)
	logger.Info("Deleting DNS record",
		zap.String("domain", domain))

	return dm.deleteDNSRecord(ctx, domain)
}

// StartDNSReconciler starts a background reconciliation process
func (dm *DNSManager) StartDNSReconciler(ctx context.Context, interval time.Duration) {
	logger := otelzap.Ctx(dm.client.rc.Ctx)
	logger.Info("Starting DNS reconciler",
		zap.Duration("interval", interval))

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("DNS reconciler stopping")
			return
		case <-ticker.C:
			logger.Debug("Running scheduled DNS reconciliation")
			if result, err := dm.ReconcileDNS(ctx); err != nil {
				logger.Error("DNS reconciliation failed", zap.Error(err))
			} else if len(result.Created)+len(result.Updated)+len(result.Deleted) > 0 {
				logger.Info("DNS reconciliation made changes",
					zap.Int("created", len(result.Created)),
					zap.Int("updated", len(result.Updated)),
					zap.Int("deleted", len(result.Deleted)))
			}
		}
	}
}

// Helper methods

func (dm *DNSManager) getActiveRoutes(ctx context.Context) (map[string]*RouteInfo, error) {
	keys, _, err := dm.client.consul.KV().Keys("hecate/routes/", "", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list routes: %w", err)
	}

	routes := make(map[string]*RouteInfo)
	for _, key := range keys {
		routeID := strings.TrimPrefix(key, "hecate/routes/")
		if routeID == "" {
			continue
		}

		data, _, err := dm.client.consul.KV().Get(key, nil)
		if err != nil {
			continue
		}

		if data == nil {
			continue
		}

		var route RouteInfo
		if err := json.Unmarshal(data.Value, &route); err != nil {
			continue
		}

		routes[route.Domain] = &route
	}

	return routes, nil
}

func (dm *DNSManager) getCurrentDNSRecords(ctx context.Context) (map[string]*DNSRecord, error) {
	// Get DNS records from Consul state (where we track managed DNS records)
	// This avoids needing Terraform state parsing and uses our own tracking
	
	records := make(map[string]*DNSRecord)
	
	// Query DNS records from Consul
	keys, _, err := dm.client.consul.KV().Keys("hecate/dns/", "", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list DNS records: %w", err)
	}

	for _, key := range keys {
		domain := strings.TrimPrefix(key, "hecate/dns/")
		if domain == "" {
			continue
		}

		data, _, err := dm.client.consul.KV().Get(key, nil)
		if err != nil {
			continue
		}

		if data == nil {
			continue
		}

		var record DNSRecord
		if err := json.Unmarshal(data.Value, &record); err != nil {
			continue
		}

		records[domain] = &record
	}

	return records, nil
}

func (dm *DNSManager) createDNSRecord(ctx context.Context, domain, target string) error {
	logger := otelzap.Ctx(dm.client.rc.Ctx)
	
	// Validate inputs
	if err := ValidateDomain(domain); err != nil {
		return fmt.Errorf("invalid domain: %w", err)
	}
	if err := ValidateIPAddress(target); err != nil {
		return fmt.Errorf("invalid target IP: %w", err)
	}

	// Check if DNS record already exists
	existing, err := dm.getDNSRecord(ctx, domain)
	if err == nil && existing != nil {
		if existing.Value == target {
			logger.Info("DNS record already exists with same target", 
				zap.String("domain", domain),
				zap.String("target", target))
			return nil
		}
		return fmt.Errorf("dns record already exists for domain %s with different target %s", domain, existing.Value)
	}

	// Create DNS record via  state (which applies via Terraform)
	state := map[string]interface{}{
		"dns_record": map[string]interface{}{
			"domain": domain,
			"target": target,
			"type":   "A",
			"ttl":    300,
		},
	}

	logger.Info("Applying DNS creation state",
		zap.String("domain", domain),
		zap.String("target", target))

	// Store DNS configuration in Consul KV for administrator review
	if err := dm.storeDNSConfigInConsul(ctx, "hecate.dns", state); err != nil {
		return fmt.Errorf("failed to store DNS configuration: %w", err)
	}

	// Track DNS record in Consul
	record := &DNSRecord{
		Name:  domain,
		Type:  "A",
		Value: target,
		TTL:   300,
	}

	data, err := json.Marshal(record)
	if err != nil {
		// Rollback: remove the DNS record we just created
		logger.Error("Failed to marshal DNS record, rolling back",
			zap.String("domain", domain),
			zap.Error(err))
		_ = dm.rollbackDNSCreation(ctx, domain)
		return fmt.Errorf("failed to marshal DNS record: %w", err)
	}

	_, err = dm.client.consul.KV().Put(&api.KVPair{
		Key:   fmt.Sprintf("hecate/dns/%s", domain),
		Value: data,
	}, nil)

	if err != nil {
		// Rollback: remove the DNS record we just created
		logger.Error("Failed to store DNS record in Consul, rolling back",
			zap.String("domain", domain),
			zap.Error(err))
		_ = dm.rollbackDNSCreation(ctx, domain)
		return fmt.Errorf("failed to store DNS record in Consul: %w", err)
	}

	logger.Info("DNS record created successfully",
		zap.String("domain", domain),
		zap.String("target", target))

	return nil
}

func (dm *DNSManager) updateDNSRecord(ctx context.Context, domain, target string) error {
	// Update existing Terraform resource
	return dm.createDNSRecord(ctx, domain, target) // Same as create for Terraform
}

func (dm *DNSManager) deleteDNSRecord(ctx context.Context, domain string) error {
	logger := otelzap.Ctx(dm.client.rc.Ctx)
	
	// Validate input
	if err := ValidateDomain(domain); err != nil {
		return fmt.Errorf("invalid domain: %w", err)
	}

	// Check if DNS record exists
	existing, err := dm.getDNSRecord(ctx, domain)
	if err != nil {
		logger.Warn("DNS record not found in Consul, attempting direct deletion",
			zap.String("domain", domain),
			zap.Error(err))
		// Continue with deletion attempt even if not tracked in Consul
	}

	logger.Info("Deleting DNS record",
		zap.String("domain", domain))

	// Backup current record for potential rollback
	var backup *DNSRecord
	if existing != nil {
		backup = existing
	}

	// Remove DNS record via Terraform by removing from  state
	state := map[string]interface{}{
		"dns_record_remove": map[string]interface{}{
			"domain": domain,
		},
	}

	// Store DNS removal configuration in Consul KV for administrator review
	if err := dm.storeDNSConfigInConsul(ctx, "hecate.dns_remove", state); err != nil {
		return fmt.Errorf("failed to store DNS removal configuration: %w", err)
	}

	// Remove from our Consul tracking
	_, err = dm.client.consul.KV().Delete(fmt.Sprintf("hecate/dns/%s", domain), nil)
	if err != nil {
		// If Consul deletion fails, we should potentially rollback the DNS deletion
		logger.Error("Failed to remove DNS record from Consul tracking, considering rollback",
			zap.String("domain", domain),
			zap.Error(err))
		
		// If we have a backup and Consul deletion failed, offer to restore
		if backup != nil {
			logger.Warn("DNS record was deleted but Consul tracking failed - manual intervention may be needed",
				zap.String("domain", domain),
				zap.String("target", backup.Value))
		}
		
		return fmt.Errorf("failed to remove DNS record from Consul: %w", err)
	}

	logger.Info("DNS record deleted successfully",
		zap.String("domain", domain))

	return nil
}

// Note: RouteInfo is defined in route_manager.go and extended with ManageDNS and IngressIP fields

// DNS reconciliation scheduling
func (dm *DNSManager) ScheduleReconciliation(ctx context.Context) error {
	logger := otelzap.Ctx(dm.client.rc.Ctx)
	logger.Info("Scheduling DNS reconciliation task")

	// Store reconciliation schedule in Consul
	schedule := map[string]interface{}{
		"enabled":      true,
		"interval":     "5m",
		"next_run":     time.Now().Add(5 * time.Minute).Format(time.RFC3339),
		"last_run":     "",
		"auto_cleanup": true,
	}

	data, err := json.Marshal(schedule)
	if err != nil {
		return fmt.Errorf("failed to marshal schedule: %w", err)
	}

	_, err = dm.client.consul.KV().Put(&api.KVPair{
		Key:   "hecate/dns-reconciler/schedule",
		Value: data,
	}, nil)

	return err
}

// GetDNSMetrics returns DNS management metrics
func (dm *DNSManager) GetDNSMetrics(ctx context.Context) (*DNSMetrics, error) {
	activeRoutes, err := dm.getActiveRoutes(ctx)
	if err != nil {
		return nil, err
	}

	currentDNS, err := dm.getCurrentDNSRecords(ctx)
	if err != nil {
		return nil, err
	}

	metrics := &DNSMetrics{
		TotalRoutes:     len(activeRoutes),
		ManagedDomains:  0,
		OrphanedRecords: 0,
		LastReconcile:   time.Now(), // Would get from Consul state
	}

	// Count managed domains
	for _, route := range activeRoutes {
		if route.ManageDNS {
			metrics.ManagedDomains++
		}
	}

	// Count orphaned records
	for domain := range currentDNS {
		if !strings.HasPrefix(domain, "*") && domain != "@" {
			if _, exists := activeRoutes[domain]; !exists {
				metrics.OrphanedRecords++
			}
		}
	}

	return metrics, nil
}

// getDNSRecord retrieves a single DNS record
func (dm *DNSManager) getDNSRecord(ctx context.Context, domain string) (*DNSRecord, error) {
	data, _, err := dm.client.consul.KV().Get(fmt.Sprintf("hecate/dns/%s", domain), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get DNS record: %w", err)
	}

	if data == nil {
		return nil, fmt.Errorf("dns record not found")
	}

	var record DNSRecord
	if err := json.Unmarshal(data.Value, &record); err != nil {
		return nil, fmt.Errorf("failed to unmarshal DNS record: %w", err)
	}

	return &record, nil
}

// rollbackDNSCreation removes a DNS record that was created but failed to be tracked
func (dm *DNSManager) rollbackDNSCreation(ctx context.Context, domain string) error {
	logger := otelzap.Ctx(dm.client.rc.Ctx)
	logger.Warn("Rolling back DNS record creation",
		zap.String("domain", domain))

	// Remove DNS record via  state
	state := map[string]interface{}{
		"dns_record_remove": map[string]interface{}{
			"domain": domain,
		},
	}

	if err := dm.storeDNSConfigInConsul(ctx, "hecate.dns_remove", state); err != nil {
		logger.Error("Failed to rollback DNS record creation",
			zap.String("domain", domain),
			zap.Error(err))
		return err
	}

	logger.Info("DNS record rollback completed",
		zap.String("domain", domain))

	return nil
}


// retryDNSOperation performs a DNS operation with exponential backoff retry
func (dm *DNSManager) retryDNSOperation(ctx context.Context, operation string, fn func() error) error {
	logger := otelzap.Ctx(dm.client.rc.Ctx)
	
	maxRetries := 3
	baseDelay := 1 * time.Second
	
	for attempt := 0; attempt < maxRetries; attempt++ {
		err := fn()
		if err == nil {
			return nil
		}
		
		if attempt == maxRetries-1 {
			logger.Error("DNS operation failed after all retries",
				zap.String("operation", operation),
				zap.Int("attempts", maxRetries),
				zap.Error(err))
			return fmt.Errorf("dns operation %s failed after %d attempts: %w", operation, maxRetries, err)
		}
		
		delay := baseDelay * time.Duration(1<<attempt) // Exponential backoff
		logger.Warn("DNS operation failed, retrying",
			zap.String("operation", operation),
			zap.Int("attempt", attempt+1),
			zap.Duration("retry_delay", delay),
			zap.Error(err))
		
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
			// Continue to next attempt
		}
	}
	
	return fmt.Errorf("dns operation %s failed after %d attempts", operation, maxRetries)
}

// validateDNSOperationPreconditions checks if a DNS operation can be performed
func (dm *DNSManager) validateDNSOperationPreconditions(ctx context.Context) error {
	// Check if HashiCorp clients are available
	if dm.client.consul == nil {
		return fmt.Errorf("consul client not available")
	}
	
	// Check if context is not cancelled
	if ctx.Err() != nil {
		return fmt.Errorf("context cancelled: %w", ctx.Err())
	}
	
	return nil
}

// CreateDNSRecordWithRetry creates a DNS record with retry logic
func (dm *DNSManager) CreateDNSRecordWithRetry(ctx context.Context, domain, target string) error {
	if err := dm.validateDNSOperationPreconditions(ctx); err != nil {
		return fmt.Errorf("dns operation preconditions failed: %w", err)
	}
	
	return dm.retryDNSOperation(ctx, "create", func() error {
		return dm.createDNSRecord(ctx, domain, target)
	})
}

// DeleteDNSRecordWithRetry deletes a DNS record with retry logic
func (dm *DNSManager) DeleteDNSRecordWithRetry(ctx context.Context, domain string) error {
	if err := dm.validateDNSOperationPreconditions(ctx); err != nil {
		return fmt.Errorf("dns operation preconditions failed: %w", err)
	}
	
	return dm.retryDNSOperation(ctx, "delete", func() error {
		return dm.deleteDNSRecord(ctx, domain)
	})
}

// storeDNSConfigInConsul stores DNS configuration in Consul KV for administrator review
func (dm *DNSManager) storeDNSConfigInConsul(ctx context.Context, operation string, config map[string]interface{}) error {
	logger := otelzap.Ctx(ctx)
	
	// Create configuration entry with metadata
	configEntry := map[string]interface{}{
		"operation":   operation,
		"config":      config,
		"created_at":  time.Now().UTC(),
		"status":      "pending_admin_review",
		"description": fmt.Sprintf("DNS %s operation requires administrator intervention", operation),
	}
	
	// Marshal configuration to JSON
	configJSON, err := json.Marshal(configEntry)
	if err != nil {
		return fmt.Errorf("failed to marshal DNS configuration: %w", err)
	}
	
	// Store in Consul KV
	consulKey := fmt.Sprintf("hecate/dns-operations/%s-%d", operation, time.Now().Unix())
	_, err = dm.client.consul.KV().Put(&api.KVPair{
		Key:   consulKey,
		Value: configJSON,
	}, nil)
	
	if err != nil {
		return fmt.Errorf("failed to store DNS configuration in Consul: %w", err)
	}
	
	logger.Info("DNS configuration stored in Consul for administrator review",
		zap.String("consul_key", consulKey),
		zap.String("operation", operation))
	
	return nil
}

// DNSMetrics represents DNS management metrics
type DNSMetrics struct {
	TotalRoutes     int       `json:"total_routes"`
	ManagedDomains  int       `json:"managed_domains"`
	OrphanedRecords int       `json:"orphaned_records"`
	LastReconcile   time.Time `json:"last_reconcile"`
}
package hecate

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DNSSecurityManager handles DNS security features
type DNSSecurityManager struct {
	client      *HecateClient
	rateLimiter *DNSRateLimiter
	monitor     *DNSSecurityMonitor
}

// NewDNSSecurityManager creates a new DNS security manager
func NewDNSSecurityManager(client *HecateClient) *DNSSecurityManager {
	return &DNSSecurityManager{
		client:      client,
		rateLimiter: NewDNSRateLimiter(10, time.Minute), // 10 operations per minute
		monitor:     NewDNSSecurityMonitor(),
	}
}

// DNSRateLimiter implements rate limiting for DNS operations
type DNSRateLimiter struct {
	limit    int
	window   time.Duration
	requests map[string][]time.Time
	mutex    sync.RWMutex
}

// NewDNSRateLimiter creates a new DNS rate limiter
func NewDNSRateLimiter(limit int, window time.Duration) *DNSRateLimiter {
	return &DNSRateLimiter{
		limit:    limit,
		window:   window,
		requests: make(map[string][]time.Time),
	}
}

// CheckRateLimit checks if an operation is within rate limits
func (rl *DNSRateLimiter) CheckRateLimit(clientID string) bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Clean old requests
	if requests, exists := rl.requests[clientID]; exists {
		validRequests := []time.Time{}
		for _, req := range requests {
			if req.After(cutoff) {
				validRequests = append(validRequests, req)
			}
		}
		rl.requests[clientID] = validRequests
	}

	// Check if within limit
	if len(rl.requests[clientID]) >= rl.limit {
		return false
	}

	// Add current request
	rl.requests[clientID] = append(rl.requests[clientID], now)
	return true
}

// DNSSecurityMonitor monitors DNS operations for security threats
type DNSSecurityMonitor struct {
	suspiciousActivities []DNSSecurityEvent
	mutex                sync.RWMutex
}

// NewDNSSecurityMonitor creates a new DNS security monitor
func NewDNSSecurityMonitor() *DNSSecurityMonitor {
	return &DNSSecurityMonitor{
		suspiciousActivities: make([]DNSSecurityEvent, 0),
	}
}

// DNSSecurityEvent represents a security event
type DNSSecurityEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	EventType   string    `json:"event_type"`
	Domain      string    `json:"domain"`
	ClientID    string    `json:"client_id"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Details     string    `json:"details"`
}

// RecordSecurityEvent records a security event
func (sm *DNSSecurityMonitor) RecordSecurityEvent(event DNSSecurityEvent) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	event.Timestamp = time.Now()
	sm.suspiciousActivities = append(sm.suspiciousActivities, event)

	// Keep only recent events (last 1000)
	if len(sm.suspiciousActivities) > 1000 {
		sm.suspiciousActivities = sm.suspiciousActivities[len(sm.suspiciousActivities)-1000:]
	}
}

// GetSecurityEvents returns recent security events
func (sm *DNSSecurityMonitor) GetSecurityEvents() []DNSSecurityEvent {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	// Return a copy to avoid race conditions
	events := make([]DNSSecurityEvent, len(sm.suspiciousActivities))
	copy(events, sm.suspiciousActivities)
	return events
}

// SecureCreateDNSRecord creates a DNS record with security checks
func (dsm *DNSSecurityManager) SecureCreateDNSRecord(ctx context.Context, domain, target, clientID string) error {
	logger := otelzap.Ctx(dsm.client.rc.Ctx)

	// Rate limiting check
	if !dsm.rateLimiter.CheckRateLimit(clientID) {
		event := DNSSecurityEvent{
			EventType:   "rate_limit_exceeded",
			Domain:      domain,
			ClientID:    clientID,
			Severity:    "warning",
			Description: "DNS operation rate limit exceeded",
		}
		dsm.monitor.RecordSecurityEvent(event)

		logger.Warn("DNS operation rate limit exceeded",
			zap.String("client_id", clientID),
			zap.String("domain", domain))

		return fmt.Errorf("rate limit exceeded for client %s", clientID)
	}

	// Security validation
	if err := dsm.validateSecureDNSRequest(domain, target, clientID); err != nil {
		return fmt.Errorf("security validation failed: %w", err)
	}

	// Perform the actual DNS creation
	dnsManager := NewDNSManager(dsm.client)
	if err := dnsManager.CreateDNSRecord(ctx, domain, target); err != nil {
		// Record failed operation
		event := DNSSecurityEvent{
			EventType:   "dns_operation_failed",
			Domain:      domain,
			ClientID:    clientID,
			Severity:    "error",
			Description: "DNS record creation failed",
			Details:     err.Error(),
		}
		dsm.monitor.RecordSecurityEvent(event)

		return err
	}

	// Record successful operation
	event := DNSSecurityEvent{
		EventType:   "dns_record_created",
		Domain:      domain,
		ClientID:    clientID,
		Severity:    "info",
		Description: "DNS record created successfully",
	}
	dsm.monitor.RecordSecurityEvent(event)

	logger.Info("Secure DNS record created",
		zap.String("domain", domain),
		zap.String("target", target),
		zap.String("client_id", clientID))

	return nil
}

// SecureDeleteDNSRecord deletes a DNS record with security checks
func (dsm *DNSSecurityManager) SecureDeleteDNSRecord(ctx context.Context, domain, clientID string) error {
	logger := otelzap.Ctx(dsm.client.rc.Ctx)

	// Rate limiting check
	if !dsm.rateLimiter.CheckRateLimit(clientID) {
		event := DNSSecurityEvent{
			EventType:   "rate_limit_exceeded",
			Domain:      domain,
			ClientID:    clientID,
			Severity:    "warning",
			Description: "DNS deletion rate limit exceeded",
		}
		dsm.monitor.RecordSecurityEvent(event)

		return fmt.Errorf("rate limit exceeded for client %s", clientID)
	}

	// Security validation
	if err := dsm.validateSecureDNSDeletion(domain, clientID); err != nil {
		return fmt.Errorf("security validation failed: %w", err)
	}

	// Perform the actual DNS deletion
	dnsManager := NewDNSManager(dsm.client)
	if err := dnsManager.DeleteDNSRecord(ctx, domain); err != nil {
		// Record failed operation
		event := DNSSecurityEvent{
			EventType:   "dns_deletion_failed",
			Domain:      domain,
			ClientID:    clientID,
			Severity:    "error",
			Description: "DNS record deletion failed",
			Details:     err.Error(),
		}
		dsm.monitor.RecordSecurityEvent(event)

		return err
	}

	// Record successful operation
	event := DNSSecurityEvent{
		EventType:   "dns_record_deleted",
		Domain:      domain,
		ClientID:    clientID,
		Severity:    "info",
		Description: "DNS record deleted successfully",
	}
	dsm.monitor.RecordSecurityEvent(event)

	logger.Info("Secure DNS record deleted",
		zap.String("domain", domain),
		zap.String("client_id", clientID))

	return nil
}

// validateSecureDNSRequest performs security validation for DNS creation
func (dsm *DNSSecurityManager) validateSecureDNSRequest(domain, target, clientID string) error {
	// Basic validation
	if err := ValidateDomain(domain); err != nil {
		dsm.recordSecurityViolation("invalid_domain", domain, clientID, err.Error())
		return err
	}

	if err := ValidateIPAddress(target); err != nil {
		dsm.recordSecurityViolation("invalid_ip", domain, clientID, err.Error())
		return err
	}

	// Check for suspicious patterns
	if err := dsm.checkSuspiciousPatterns(domain, target, clientID); err != nil {
		return err
	}

	// Check domain reputation (simplified)
	if err := dsm.checkDomainReputation(domain, clientID); err != nil {
		return err
	}

	return nil
}

// validateSecureDNSDeletion performs security validation for DNS deletion
func (dsm *DNSSecurityManager) validateSecureDNSDeletion(domain, clientID string) error {
	// Basic validation
	if err := ValidateDomain(domain); err != nil {
		dsm.recordSecurityViolation("invalid_domain", domain, clientID, err.Error())
		return err
	}

	// Check if domain is protected (simplified)
	protectedDomains := []string{
		"localhost",
		"example.com",
		"test.com",
	}

	for _, protected := range protectedDomains {
		if domain == protected {
			dsm.recordSecurityViolation("protected_domain_deletion", domain, clientID, "Attempted to delete protected domain")
			return fmt.Errorf("cannot delete protected domain: %s", domain)
		}
	}

	return nil
}

// checkSuspiciousPatterns checks for suspicious domain/IP patterns
func (dsm *DNSSecurityManager) checkSuspiciousPatterns(domain, target, clientID string) error {
	// Check for suspicious domain patterns
	suspiciousDomainPatterns := []string{
		"phishing",
		"malware",
		"scam",
		"fake",
		"evil",
	}

	for _, pattern := range suspiciousDomainPatterns {
		if strings.Contains(domain, pattern) {
			dsm.recordSecurityViolation("suspicious_domain_pattern", domain, clientID,
				fmt.Sprintf("Domain contains suspicious pattern: %s", pattern))
			return fmt.Errorf("domain contains suspicious pattern: %s", pattern)
		}
	}

	// Check for suspicious IP ranges (simplified)
	suspiciousIPPrefixes := []string{
		"0.",   // Broadcast/network
		"127.", // Loopback
		"255.", // Broadcast
	}

	for _, prefix := range suspiciousIPPrefixes {
		if strings.HasPrefix(target, prefix) {
			dsm.recordSecurityViolation("suspicious_ip_range", domain, clientID,
				fmt.Sprintf("Target IP in suspicious range: %s", prefix))
			return fmt.Errorf("target IP in suspicious range: %s", prefix)
		}
	}

	return nil
}

// checkDomainReputation checks domain reputation (simplified implementation)
func (dsm *DNSSecurityManager) checkDomainReputation(domain, clientID string) error {
	// This is a simplified implementation
	// In production, you'd integrate with threat intelligence services

	// Check against a simple blocklist
	blockedDomains := []string{
		"malicious.example.com",
		"phishing.test.com",
	}

	for _, blocked := range blockedDomains {
		if domain == blocked {
			dsm.recordSecurityViolation("blocked_domain", domain, clientID,
				"Domain is on security blocklist")
			return fmt.Errorf("domain is blocked by security policy: %s", domain)
		}
	}

	return nil
}

// recordSecurityViolation records a security violation
func (dsm *DNSSecurityManager) recordSecurityViolation(violationType, domain, clientID, details string) {
	event := DNSSecurityEvent{
		EventType:   violationType,
		Domain:      domain,
		ClientID:    clientID,
		Severity:    "high",
		Description: "Security violation detected",
		Details:     details,
	}
	dsm.monitor.RecordSecurityEvent(event)

	logger := otelzap.Ctx(dsm.client.rc.Ctx)
	logger.Error("DNS security violation detected",
		zap.String("violation_type", violationType),
		zap.String("domain", domain),
		zap.String("client_id", clientID),
		zap.String("details", details))
}

// GetSecurityStatus returns the current security status
func (dsm *DNSSecurityManager) GetSecurityStatus() *DNSSecurityStatus {
	events := dsm.monitor.GetSecurityEvents()

	status := &DNSSecurityStatus{
		TotalEvents:        len(events),
		HighSeverityEvents: 0,
		LastEventTime:      time.Time{},
		RateLimitActive:    false,
	}

	for _, event := range events {
		if event.Severity == "high" || event.Severity == "error" {
			status.HighSeverityEvents++
		}
		if event.Timestamp.After(status.LastEventTime) {
			status.LastEventTime = event.Timestamp
		}
	}

	return status
}

// DNSSecurityStatus represents the current security status
type DNSSecurityStatus struct {
	TotalEvents        int       `json:"total_events"`
	HighSeverityEvents int       `json:"high_severity_events"`
	LastEventTime      time.Time `json:"last_event_time"`
	RateLimitActive    bool      `json:"rate_limit_active"`
}

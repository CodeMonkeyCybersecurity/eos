package monitoring

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// AlertManager manages alert rules and handles alert firing
type AlertManager struct {
	rc                *eos_io.RuntimeContext
	rules             map[string]*AlertRule
	activeAlerts      map[string]*Alert
	alertHistory      []*Alert
	mutex             sync.RWMutex
	notificationQueue chan *Alert
	stopCh            chan struct{}
}

// AlertEvaluator evaluates alert conditions against metrics
type AlertEvaluator struct {
	rc *eos_io.RuntimeContext
}

// NotificationChannel represents a notification channel configuration
type NotificationChannel struct {
	Type   string                 `json:"type"` // email, slack, webhook, pagerduty
	Name   string                 `json:"name"`
	Config map[string]interface{} `json:"config"`
}

// EmailNotificationConfig represents email notification configuration
type EmailNotificationConfig struct {
	SMTPHost     string   `json:"smtp_host"`
	SMTPPort     int      `json:"smtp_port"`
	SMTPUser     string   `json:"smtp_user"`
	SMTPPassword string   `json:"smtp_password"`
	From         string   `json:"from"`
	To           []string `json:"to"`
	Subject      string   `json:"subject"`
	Template     string   `json:"template"`
}

// SlackNotificationConfig represents Slack notification configuration
type SlackNotificationConfig struct {
	WebhookURL string `json:"webhook_url"`
	Channel    string `json:"channel"`
	Username   string `json:"username"`
	IconEmoji  string `json:"icon_emoji"`
	Template   string `json:"template"`
}

// WebhookNotificationConfig represents webhook notification configuration
type WebhookNotificationConfig struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	Timeout time.Duration     `json:"timeout"`
}

// PagerDutyNotificationConfig represents PagerDuty notification configuration
type PagerDutyNotificationConfig struct {
	IntegrationKey string `json:"integration_key"`
	Severity       string `json:"severity"`
	Component      string `json:"component"`
	Group          string `json:"group"`
	Class          string `json:"class"`
}

// NewAlertManager creates a new alert manager
func NewAlertManager(rc *eos_io.RuntimeContext) *AlertManager {
	return &AlertManager{
		rc:                rc,
		rules:             make(map[string]*AlertRule),
		activeAlerts:      make(map[string]*Alert),
		alertHistory:      make([]*Alert, 0),
		notificationQueue: make(chan *Alert, 100),
		stopCh:            make(chan struct{}),
	}
}

// Start starts the alert manager
func (am *AlertManager) Start(ctx context.Context) {
	logger := otelzap.Ctx(am.rc.Ctx)
	logger.Info("Starting alert manager")

	// Start notification processor
	go am.processNotifications(ctx)

	// Start alert evaluation loop
	go am.evaluateAlerts(ctx)

	logger.Info("Alert manager started")
}

// Stop stops the alert manager
func (am *AlertManager) Stop() {
	logger := otelzap.Ctx(am.rc.Ctx)
	logger.Info("Stopping alert manager")

	close(am.stopCh)
	close(am.notificationQueue)

	logger.Info("Alert manager stopped")
}

// AddRule adds an alert rule
func (am *AlertManager) AddRule(rule *AlertRule) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	logger := otelzap.Ctx(am.rc.Ctx)
	logger.Info("Adding alert rule",
		zap.String("id", rule.ID),
		zap.String("name", rule.Name))

	am.rules[rule.ID] = rule
	return nil
}

// RemoveRule removes an alert rule
func (am *AlertManager) RemoveRule(ruleID string) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	logger := otelzap.Ctx(am.rc.Ctx)
	logger.Info("Removing alert rule",
		zap.String("id", ruleID))

	delete(am.rules, ruleID)
	return nil
}

// GetRules returns all alert rules
func (am *AlertManager) GetRules() map[string]*AlertRule {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	rules := make(map[string]*AlertRule)
	for id, rule := range am.rules {
		rules[id] = rule
	}
	return rules
}

// GetActiveAlerts returns all active alerts
func (am *AlertManager) GetActiveAlerts() map[string]*Alert {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	alerts := make(map[string]*Alert)
	for id, alert := range am.activeAlerts {
		alerts[id] = alert
	}
	return alerts
}

// GetAlertHistory returns alert history
func (am *AlertManager) GetAlertHistory(limit int) []*Alert {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	if limit <= 0 || limit > len(am.alertHistory) {
		limit = len(am.alertHistory)
	}

	history := make([]*Alert, limit)
	copy(history, am.alertHistory[:limit])
	return history
}

// evaluateAlerts evaluates all alert rules against current metrics
func (am *AlertManager) evaluateAlerts(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second) // Evaluate every 30 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-am.stopCh:
			return
		case <-ticker.C:
			am.evaluateAllRules()
		}
	}
}

// evaluateAllRules evaluates all alert rules
func (am *AlertManager) evaluateAllRules() {
	logger := otelzap.Ctx(am.rc.Ctx)

	// Collect current metrics
	collector := NewMetricsCollector(am.rc, "http://localhost:2019", "")
	snapshot, err := collector.CollectMetrics()
	if err != nil {
		logger.Error("Failed to collect metrics for alert evaluation", zap.Error(err))
		return
	}

	am.mutex.Lock()
	defer am.mutex.Unlock()

	for _, rule := range am.rules {
		if !rule.Enabled {
			continue
		}

		shouldFire := am.evaluateRule(rule, snapshot)
		alertID := fmt.Sprintf("%s_%s", rule.ID, time.Now().Format("20060102"))

		if shouldFire {
			// Check if alert is already active
			if _, exists := am.activeAlerts[alertID]; !exists {
				// Fire new alert
				alert := &Alert{
					ID:          alertID,
					RuleID:      rule.ID,
					Name:        rule.Name,
					Description: rule.Description,
					Severity:    rule.Severity,
					Status:      "firing",
					FiredAt:     time.Now(),
					Labels:      rule.Labels,
					Threshold:   rule.Threshold,
				}

				am.activeAlerts[alertID] = alert
				am.alertHistory = append([]*Alert{alert}, am.alertHistory...)

				// Queue notification
				select {
				case am.notificationQueue <- alert:
				default:
					logger.Warn("Notification queue full, dropping alert")
				}

				logger.Warn("Alert fired",
					zap.String("rule_id", rule.ID),
					zap.String("alert_id", alertID),
					zap.String("name", rule.Name))
			}
		} else {
			// Check if we should resolve an active alert
			if alert, exists := am.activeAlerts[alertID]; exists {
				now := time.Now()
				alert.Status = "resolved"
				alert.ResolvedAt = &now

				delete(am.activeAlerts, alertID)

				logger.Info("Alert resolved",
					zap.String("rule_id", rule.ID),
					zap.String("alert_id", alertID),
					zap.String("name", rule.Name))
			}
		}
	}
}

// evaluateRule evaluates a single alert rule against metrics
func (am *AlertManager) evaluateRule(rule *AlertRule, snapshot *MetricsSnapshot) bool {
	logger := otelzap.Ctx(am.rc.Ctx)
	_ = logger // Suppress unused variable warning

	// Simple condition evaluation
	// TODO: Implement a more sophisticated expression evaluator
	switch rule.Condition {
	case "route_error_rate_high":
		for _, metrics := range snapshot.Routes {
			if metrics.ErrorRate > rule.Threshold {
				return true
			}
		}
	case "route_response_time_high":
		for _, metrics := range snapshot.Routes {
			if metrics.ResponseTime.Seconds() > rule.Threshold {
				return true
			}
		}
	case "route_unhealthy":
		for _, metrics := range snapshot.Routes {
			if metrics.HealthStatus != "healthy" {
				return true
			}
		}
	case "system_load_high":
		return snapshot.System.SystemLoad > rule.Threshold
	case "memory_usage_high":
		return snapshot.System.MemoryUsage > rule.Threshold
	case "disk_usage_high":
		return snapshot.System.DiskUsage > rule.Threshold
	case "service_unhealthy":
		for _, health := range snapshot.Services {
			if health.Status != "healthy" {
				return true
			}
		}
	default:
		logger.Warn("Unknown alert condition",
			zap.String("condition", rule.Condition))
	}

	return false
}

// processNotifications processes queued notifications
func (am *AlertManager) processNotifications(ctx context.Context) {
	logger := otelzap.Ctx(am.rc.Ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-am.stopCh:
			return
		case alert := <-am.notificationQueue:
			if alert == nil {
				return
			}

			// Get the rule to find notification actions
			am.mutex.RLock()
			rule, exists := am.rules[alert.RuleID]
			am.mutex.RUnlock()

			if !exists {
				logger.Warn("Rule not found for alert",
					zap.String("rule_id", alert.RuleID))
				continue
			}

			// Send notifications for each action
			for _, action := range rule.Actions {
				go am.sendNotification(alert, action)
			}
		}
	}
}

// sendNotification sends a notification via the specified action
func (am *AlertManager) sendNotification(alert *Alert, action AlertAction) {
	logger := otelzap.Ctx(am.rc.Ctx)

	logger.Info("Sending notification",
		zap.String("alert_id", alert.ID),
		zap.String("type", action.Type))

	switch action.Type {
	case "email":
		am.sendEmailNotification(alert, action.Config)
	case "slack":
		am.sendSlackNotification(alert, action.Config)
	case "webhook":
		am.sendWebhookNotification(alert, action.Config)
	case "pagerduty":
		am.sendPagerDutyNotification(alert, action.Config)
	default:
		logger.Warn("Unknown notification type",
			zap.String("type", action.Type))
	}
}

// sendEmailNotification sends an email notification
func (am *AlertManager) sendEmailNotification(alert *Alert, config map[string]interface{}) {
	logger := otelzap.Ctx(am.rc.Ctx)

	// TODO: Implement email sending
	logger.Info("Would send email notification",
		zap.String("alert_id", alert.ID),
		zap.String("subject", fmt.Sprintf("Alert: %s", alert.Name)))
}

// sendSlackNotification sends a Slack notification
func (am *AlertManager) sendSlackNotification(alert *Alert, config map[string]interface{}) {
	logger := otelzap.Ctx(am.rc.Ctx)

	webhookURL, ok := config["webhook_url"].(string)
	if !ok {
		logger.Error("Invalid Slack webhook URL")
		return
	}

	// Create Slack message
	message := map[string]interface{}{
		"text": fmt.Sprintf("🚨 Alert: %s", alert.Name),
		"attachments": []map[string]interface{}{
			{
				"color": getSeverityColor(alert.Severity),
				"fields": []map[string]interface{}{
					{
						"title": "Alert",
						"value": alert.Name,
						"short": true,
					},
					{
						"title": "Severity",
						"value": alert.Severity,
						"short": true,
					},
					{
						"title": "Description",
						"value": alert.Description,
						"short": false,
					},
					{
						"title": "Fired At",
						"value": alert.FiredAt.Format(time.RFC3339),
						"short": true,
					},
				},
			},
		},
	}

	// Send to Slack
	body, err := json.Marshal(message)
	if err != nil {
		logger.Error("Failed to marshal Slack message", zap.Error(err))
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(webhookURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		logger.Error("Failed to send Slack notification", zap.Error(err))
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		logger.Error("Slack notification failed",
			zap.Int("status_code", resp.StatusCode))
		return
	}

	logger.Info("Slack notification sent successfully",
		zap.String("alert_id", alert.ID))
}

// sendWebhookNotification sends a webhook notification
func (am *AlertManager) sendWebhookNotification(alert *Alert, config map[string]interface{}) {
	logger := otelzap.Ctx(am.rc.Ctx)

	url, ok := config["url"].(string)
	if !ok {
		logger.Error("Invalid webhook URL")
		return
	}

	method := "POST"
	if m, ok := config["method"].(string); ok {
		method = m
	}

	// Create webhook payload
	payload := map[string]interface{}{
		"alert":     alert,
		"timestamp": time.Now().Unix(),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		logger.Error("Failed to marshal webhook payload", zap.Error(err))
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(am.rc.Ctx, method, url, bytes.NewBuffer(body))
	if err != nil {
		logger.Error("Failed to create webhook request", zap.Error(err))
		return
	}

	req.Header.Set("Content-Type", "application/json")

	// Add custom headers
	if headers, ok := config["headers"].(map[string]interface{}); ok {
		for key, value := range headers {
			if strValue, ok := value.(string); ok {
				req.Header.Set(key, strValue)
			}
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		logger.Error("Failed to send webhook notification", zap.Error(err))
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		logger.Error("Webhook notification failed",
			zap.Int("status_code", resp.StatusCode))
		return
	}

	logger.Info("Webhook notification sent successfully",
		zap.String("alert_id", alert.ID),
		zap.String("url", url))
}

// sendPagerDutyNotification sends a PagerDuty notification
func (am *AlertManager) sendPagerDutyNotification(alert *Alert, config map[string]interface{}) {
	logger := otelzap.Ctx(am.rc.Ctx)

	integrationKey, ok := config["integration_key"].(string)
	if !ok {
		logger.Error("Invalid PagerDuty integration key")
		return
	}

	// Create PagerDuty event
	event := map[string]interface{}{
		"routing_key":  integrationKey,
		"event_action": "trigger",
		"dedup_key":    alert.ID,
		"payload": map[string]interface{}{
			"summary":   alert.Name,
			"source":    "hecate",
			"severity":  alert.Severity,
			"timestamp": alert.FiredAt.Format(time.RFC3339),
			"custom_details": map[string]interface{}{
				"description": alert.Description,
				"rule_id":     alert.RuleID,
				"labels":      alert.Labels,
			},
		},
	}

	body, err := json.Marshal(event)
	if err != nil {
		logger.Error("Failed to marshal PagerDuty event", zap.Error(err))
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post("https://events.pagerduty.com/v2/enqueue", "application/json", bytes.NewBuffer(body))
	if err != nil {
		logger.Error("Failed to send PagerDuty notification", zap.Error(err))
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusAccepted {
		logger.Error("PagerDuty notification failed",
			zap.Int("status_code", resp.StatusCode))
		return
	}

	logger.Info("PagerDuty notification sent successfully",
		zap.String("alert_id", alert.ID))
}

// getSeverityColor returns a color for Slack attachments based on severity
func getSeverityColor(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "danger"
	case "warning":
		return "warning"
	case "info":
		return "good"
	default:
		return "#808080"
	}
}

// CreateDefaultAlertRules creates a set of default alert rules
func CreateDefaultAlertRules() []*AlertRule {
	return []*AlertRule{
		{
			ID:          "route_error_rate_high",
			Name:        "High Route Error Rate",
			Description: "Route error rate is above threshold",
			Condition:   "route_error_rate_high",
			Threshold:   0.05, // 5%
			Duration:    5 * time.Minute,
			Severity:    "warning",
			Enabled:     true,
			Labels: map[string]string{
				"component": "routes",
				"type":      "error_rate",
			},
			Actions: []AlertAction{
				{
					Type: "slack",
					Config: map[string]interface{}{
						"webhook_url": "", // Should be configured
						"channel":     "#alerts",
					},
				},
			},
		},
		{
			ID:          "route_response_time_high",
			Name:        "High Route Response Time",
			Description: "Route response time is above threshold",
			Condition:   "route_response_time_high",
			Threshold:   2.0, // 2 seconds
			Duration:    5 * time.Minute,
			Severity:    "warning",
			Enabled:     true,
			Labels: map[string]string{
				"component": "routes",
				"type":      "performance",
			},
			Actions: []AlertAction{
				{
					Type: "slack",
					Config: map[string]interface{}{
						"webhook_url": "", // Should be configured
						"channel":     "#alerts",
					},
				},
			},
		},
		{
			ID:          "route_unhealthy",
			Name:        "Route Unhealthy",
			Description: "One or more routes are unhealthy",
			Condition:   "route_unhealthy",
			Threshold:   1,
			Duration:    2 * time.Minute,
			Severity:    "critical",
			Enabled:     true,
			Labels: map[string]string{
				"component": "routes",
				"type":      "availability",
			},
			Actions: []AlertAction{
				{
					Type: "slack",
					Config: map[string]interface{}{
						"webhook_url": "", // Should be configured
						"channel":     "#critical-alerts",
					},
				},
			},
		},
		{
			ID:          "system_load_high",
			Name:        "High System Load",
			Description: "System load is above threshold",
			Condition:   "system_load_high",
			Threshold:   2.0,
			Duration:    5 * time.Minute,
			Severity:    "warning",
			Enabled:     true,
			Labels: map[string]string{
				"component": "system",
				"type":      "load",
			},
			Actions: []AlertAction{
				{
					Type: "slack",
					Config: map[string]interface{}{
						"webhook_url": "", // Should be configured
						"channel":     "#alerts",
					},
				},
			},
		},
		{
			ID:          "memory_usage_high",
			Name:        "High Memory Usage",
			Description: "Memory usage is above threshold",
			Condition:   "memory_usage_high",
			Threshold:   0.9, // 90%
			Duration:    5 * time.Minute,
			Severity:    "warning",
			Enabled:     true,
			Labels: map[string]string{
				"component": "system",
				"type":      "memory",
			},
			Actions: []AlertAction{
				{
					Type: "slack",
					Config: map[string]interface{}{
						"webhook_url": "", // Should be configured
						"channel":     "#alerts",
					},
				},
			},
		},
		{
			ID:          "service_unhealthy",
			Name:        "Service Unhealthy",
			Description: "One or more services are unhealthy",
			Condition:   "service_unhealthy",
			Threshold:   1,
			Duration:    2 * time.Minute,
			Severity:    "critical",
			Enabled:     true,
			Labels: map[string]string{
				"component": "services",
				"type":      "availability",
			},
			Actions: []AlertAction{
				{
					Type: "slack",
					Config: map[string]interface{}{
						"webhook_url": "", // Should be configured
						"channel":     "#critical-alerts",
					},
				},
			},
		},
	}
}

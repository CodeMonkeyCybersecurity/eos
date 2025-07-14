package monitoring

import (
	"fmt"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewAlertManager creates a new alert manager
func NewAlertManager(config AlertingConfig) *AlertManager {
	return &AlertManager{
		config:   config,
		channels: make(map[string]AlertChannel),
		rules:    make(map[string]AlertRule),
		alerts:   make(map[string]*Alert),
	}
}

// AddChannel adds an alert channel
func (am *AlertManager) AddChannel(channel AlertChannel) {
	am.channels[channel.Name] = channel
}

// AddRule adds an alert rule
func (am *AlertManager) AddRule(rule AlertRule) {
	am.rules[rule.Name] = rule
}

// TriggerAlert triggers a new alert
func (am *AlertManager) TriggerAlert(rc *eos_io.RuntimeContext, alert *Alert) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Triggering alert",
		zap.String("alert_id", alert.ID),
		zap.String("target", alert.Target),
		zap.String("severity", string(alert.Severity)))

	// Check if alert already exists and is active
	if existingAlert, exists := am.alerts[alert.ID]; exists {
		if existingAlert.Status == AlertStatusActive {
			// Update existing alert
			existingAlert.Duration = time.Since(existingAlert.StartTime)
			logger.Debug("Updated existing alert", zap.String("alert_id", alert.ID))
			return nil
		}
	}

	// Store the new alert
	am.alerts[alert.ID] = alert

	// Send notifications if enabled
	if am.config.Enabled {
		return am.sendNotifications(rc, alert)
	}

	return nil
}

// ResolveAlert resolves an active alert
func (am *AlertManager) ResolveAlert(rc *eos_io.RuntimeContext, alertID string) error {
	logger := otelzap.Ctx(rc.Ctx)

	alert, exists := am.alerts[alertID]
	if !exists {
		return fmt.Errorf("alert not found: %s", alertID)
	}

	if alert.Status != AlertStatusActive {
		return fmt.Errorf("alert is not active: %s", alertID)
	}

	// Update alert status
	now := time.Now()
	alert.Status = AlertStatusResolved
	alert.EndTime = &now
	alert.Duration = now.Sub(alert.StartTime)

	logger.Info("Alert resolved",
		zap.String("alert_id", alertID),
		zap.String("target", alert.Target),
		zap.Duration("duration", alert.Duration))

	// Send resolution notifications
	if am.config.Enabled {
		resolvedAlert := *alert
		resolvedAlert.Message = fmt.Sprintf("RESOLVED: %s", alert.Message)
		return am.sendNotifications(rc, &resolvedAlert)
	}

	return nil
}

// AcknowledgeAlert acknowledges an alert
func (am *AlertManager) AcknowledgeAlert(rc *eos_io.RuntimeContext, alertID, acknowledgedBy string) error {
	logger := otelzap.Ctx(rc.Ctx)

	alert, exists := am.alerts[alertID]
	if !exists {
		return fmt.Errorf("alert not found: %s", alertID)
	}

	if alert.Status != AlertStatusActive {
		return fmt.Errorf("alert is not active: %s", alertID)
	}

	// Update alert acknowledgment
	now := time.Now()
	alert.Acknowledged = true
	alert.AcknowledgedBy = acknowledgedBy
	alert.AcknowledgedAt = &now

	logger.Info("Alert acknowledged",
		zap.String("alert_id", alertID),
		zap.String("target", alert.Target),
		zap.String("acknowledged_by", acknowledgedBy))

	return nil
}

// EvaluateMetrics evaluates metrics against alert rules
func (am *AlertManager) EvaluateMetrics(rc *eos_io.RuntimeContext, target *MonitoringTarget, metrics *MetricResult) {
	logger := otelzap.Ctx(rc.Ctx)

	for _, rule := range am.rules {
		if !rule.Enabled {
			continue
		}

		// Check if the rule applies to this target
		if !am.ruleAppliesToTarget(rule, target) {
			continue
		}

		// Evaluate the rule condition
		if am.evaluateRuleCondition(rule, metrics) {
			// Check cooldown period
			if am.isInCooldown(rule, target) {
				continue
			}

			// Trigger alert
			alert := &Alert{
				ID:       fmt.Sprintf("%s-%s-%d", rule.Name, target.Name, time.Now().Unix()),
				Rule:     rule.Name,
				Target:   target.Name,
				Severity: rule.Severity,
				Status:   AlertStatusActive,
				Message:  am.formatAlertMessage(rule, target, metrics),
				Details: map[string]interface{}{
					"rule_condition": rule.Condition,
					"metric_value":   am.getMetricValue(rule.Condition.Metric, metrics),
					"threshold":      rule.Condition.Threshold,
				},
				StartTime: time.Now(),
				Channels:  rule.Channels,
				Metadata:  rule.Metadata,
			}

			if err := am.TriggerAlert(rc, alert); err != nil {
				logger.Error("Failed to trigger alert",
					zap.String("rule", rule.Name),
					zap.String("target", target.Name),
					zap.Error(err))
			}
		}
	}
}

// GetActiveAlerts returns all active alerts
func (am *AlertManager) GetActiveAlerts() []*Alert {
	var activeAlerts []*Alert
	for _, alert := range am.alerts {
		if alert.Status == AlertStatusActive {
			activeAlerts = append(activeAlerts, alert)
		}
	}
	return activeAlerts
}

// GetAlertHistory returns alert history
func (am *AlertManager) GetAlertHistory(limit int) []*Alert {
	var allAlerts []*Alert
	for _, alert := range am.alerts {
		allAlerts = append(allAlerts, alert)
	}

	// Sort by start time (most recent first)
	// In a real implementation, this would be more sophisticated
	if limit > 0 && len(allAlerts) > limit {
		allAlerts = allAlerts[:limit]
	}

	return allAlerts
}

// Helper methods

func (am *AlertManager) sendNotifications(rc *eos_io.RuntimeContext, alert *Alert) error {
	logger := otelzap.Ctx(rc.Ctx)

	var wg sync.WaitGroup
	var errors []error
	var mu sync.Mutex

	for _, channelName := range alert.Channels {
		channel, exists := am.channels[channelName]
		if !exists || !channel.Enabled {
			continue
		}

		wg.Add(1)
		go func(ch AlertChannel) {
			defer wg.Done()

			if err := am.sendChannelNotification(rc, ch, alert); err != nil {
				logger.Error("Failed to send notification",
					zap.String("channel", ch.Name),
					zap.String("alert_id", alert.ID),
					zap.Error(err))

				mu.Lock()
				errors = append(errors, err)
				mu.Unlock()
			}
		}(channel)
	}

	wg.Wait()

	if len(errors) > 0 {
		return fmt.Errorf("failed to send notifications to %d channels", len(errors))
	}

	return nil
}

func (am *AlertManager) sendChannelNotification(rc *eos_io.RuntimeContext, channel AlertChannel, alert *Alert) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Sending notification",
		zap.String("channel", channel.Name),
		zap.String("type", string(channel.Type)),
		zap.String("alert_id", alert.ID))

	// Format message using template
	message := am.formatNotificationMessage(alert)

	switch channel.Type {
	case AlertChannelTypeEmail:
		return am.sendEmailNotification(channel, alert, message)
	case AlertChannelTypeSlack:
		return am.sendSlackNotification(channel, alert, message)
	case AlertChannelTypeWebhook:
		return am.sendWebhookNotification(channel, alert, message)
	case AlertChannelTypeSMS:
		return am.sendSMSNotification(channel, alert, message)
	case AlertChannelTypePagerDuty:
		return am.sendPagerDutyNotification(channel, alert, message)
	default:
		return fmt.Errorf("unsupported channel type: %s", channel.Type)
	}
}

func (am *AlertManager) ruleAppliesToTarget(rule AlertRule, target *MonitoringTarget) bool {
	// Simple implementation - in reality, this would be more sophisticated
	// with tag matching, environment filtering, etc.
	return true
}

func (am *AlertManager) evaluateRuleCondition(rule AlertRule, metrics *MetricResult) bool {
	metricValue := am.getMetricValue(rule.Condition.Metric, metrics)
	if metricValue == nil {
		return false
	}

	threshold := rule.Condition.Threshold

	switch rule.Condition.Operator {
	case ">":
		return am.compareFloat(metricValue) > threshold
	case "<":
		return am.compareFloat(metricValue) < threshold
	case ">=":
		return am.compareFloat(metricValue) >= threshold
	case "<=":
		return am.compareFloat(metricValue) <= threshold
	case "==":
		return am.compareFloat(metricValue) == threshold
	case "!=":
		return am.compareFloat(metricValue) != threshold
	default:
		return false
	}
}

func (am *AlertManager) getMetricValue(metricName string, metrics *MetricResult) interface{} {
	if metric, exists := metrics.Metrics[metricName]; exists {
		return metric.Value
	}
	return nil
}

func (am *AlertManager) compareFloat(value interface{}) float64 {
	switch v := value.(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int64:
		return float64(v)
	default:
		return 0.0
	}
}

func (am *AlertManager) isInCooldown(rule AlertRule, target *MonitoringTarget) bool {
	// Check if we're in cooldown period for this rule/target combination
	// This would be implemented with proper state tracking
	return false
}

func (am *AlertManager) formatAlertMessage(rule AlertRule, target *MonitoringTarget, metrics *MetricResult) string {
	metricValue := am.getMetricValue(rule.Condition.Metric, metrics)
	return fmt.Sprintf("Alert: %s - %s %s %v (threshold: %v)",
		rule.Name,
		rule.Condition.Metric,
		rule.Condition.Operator,
		metricValue,
		rule.Condition.Threshold)
}

func (am *AlertManager) formatNotificationMessage(alert *Alert) string {
	template, exists := am.config.Templates["default"]
	if !exists {
		template = "{{ .Target }} alert: {{ .Message }}"
	}

	// Simple template substitution - in reality, would use proper templating
	message := template
	message = fmt.Sprintf("%s is %s: %s", alert.Target, alert.Status, alert.Message)
	
	return message
}

// Notification method implementations (simplified)

func (am *AlertManager) sendEmailNotification(channel AlertChannel, alert *Alert, message string) error {
	// Implementation would send actual email
	fmt.Printf("Email notification sent to %s: %s\n", channel.Name, message)
	return nil
}

func (am *AlertManager) sendSlackNotification(channel AlertChannel, alert *Alert, message string) error {
	// Implementation would send to Slack webhook
	fmt.Printf("Slack notification sent to %s: %s\n", channel.Name, message)
	return nil
}

func (am *AlertManager) sendWebhookNotification(channel AlertChannel, alert *Alert, message string) error {
	// Implementation would send HTTP POST to webhook
	fmt.Printf("Webhook notification sent to %s: %s\n", channel.Name, message)
	return nil
}

func (am *AlertManager) sendSMSNotification(channel AlertChannel, alert *Alert, message string) error {
	// Implementation would send SMS
	fmt.Printf("SMS notification sent to %s: %s\n", channel.Name, message)
	return nil
}

func (am *AlertManager) sendPagerDutyNotification(channel AlertChannel, alert *Alert, message string) error {
	// Implementation would send to PagerDuty API
	fmt.Printf("PagerDuty notification sent to %s: %s\n", channel.Name, message)
	return nil
}
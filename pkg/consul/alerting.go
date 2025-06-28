// pkg/consul/alerting.go

package consul

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// AlertManager handles alert notifications
type AlertManager struct {
	config *MonitoringConfig
	client *http.Client
}

// Alert represents an alert to be sent
type Alert struct {
	Service   string    `json:"service"`
	CheckName string    `json:"check_name"`
	Status    string    `json:"status"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
	Severity  string    `json:"severity"`
}

// AlertPayload represents the structure sent to webhooks
type AlertPayload struct {
	AlertType string    `json:"alert_type"`
	Alert     Alert     `json:"alert"`
	Timestamp time.Time `json:"timestamp"`
	Source    string    `json:"source"`
}

// NewAlertManager creates a new alert manager
func NewAlertManager(config *MonitoringConfig) *AlertManager {
	return &AlertManager{
		config: config,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// SendAlert sends an alert notification
func (am *AlertManager) SendAlert(alert Alert) error {
	if !am.config.AlertingEnabled {
		return nil
	}

	payload := AlertPayload{
		AlertType: "consul_service_health",
		Alert:     alert,
		Timestamp: time.Now(),
		Source:    "eos-consul-manager",
	}

	if am.config.AlertingWebhook != "" {
		return am.sendWebhookAlert(payload)
	}

	// Could add other notification methods here (email, Slack, etc.)
	return nil
}

// sendWebhookAlert sends alert via webhook
func (am *AlertManager) sendWebhookAlert(payload AlertPayload) error {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal alert payload: %w", err)
	}

	req, err := http.NewRequest("POST", am.config.AlertingWebhook, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "eos-consul-manager/1.0")

	resp, err := am.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer func() {
		_ = resp.Body.Close() // Explicitly ignore error
	}()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned error status: %d", resp.StatusCode)
	}

	return nil
}

// SendTestAlert sends a test alert to verify configuration
func (am *AlertManager) SendTestAlert() error {
	testAlert := Alert{
		Service:   "test-service",
		CheckName: "test-check",
		Status:    "critical",
		Message:   "This is a test alert from Eos Consul Manager",
		Timestamp: time.Now(),
		Severity:  "info",
	}

	return am.SendAlert(testAlert)
}
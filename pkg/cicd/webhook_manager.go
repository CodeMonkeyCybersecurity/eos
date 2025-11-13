package cicd

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// WebhookManager handles webhook notifications and triggers
type WebhookManager struct {
	mu              sync.RWMutex
	webhooks        map[string]*WebhookConfig
	client          *http.Client
	logger          *zap.Logger
	incomingHandler WebhookHandler
}

// WebhookHandler processes incoming webhook events
type WebhookHandler interface {
	HandleWebhook(event WebhookEvent) error
}

// WebhookEvent represents an incoming webhook event
type WebhookEvent struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Source    string                 `json:"source"`
	Timestamp time.Time              `json:"timestamp"`
	Signature string                 `json:"signature"`
	Headers   map[string]string      `json:"headers"`
	Body      json.RawMessage        `json:"body"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// GitHubWebhookPayload represents a GitHub webhook payload
type GitHubWebhookPayload struct {
	Ref        string `json:"ref"`
	Before     string `json:"before"`
	After      string `json:"after"`
	Repository struct {
		Name     string `json:"name"`
		FullName string `json:"full_name"`
		CloneURL string `json:"clone_url"`
	} `json:"repository"`
	Pusher struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"pusher"`
	HeadCommit struct {
		ID        string    `json:"id"`
		Message   string    `json:"message"`
		Timestamp time.Time `json:"timestamp"`
		Author    struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		} `json:"author"`
	} `json:"head_commit"`
}

// GitLabWebhookPayload represents a GitLab webhook payload
type GitLabWebhookPayload struct {
	ObjectKind  string `json:"object_kind"`
	EventName   string `json:"event_name"`
	Ref         string `json:"ref"`
	CheckoutSHA string `json:"checkout_sha"`
	UserName    string `json:"user_name"`
	UserEmail   string `json:"user_email"`
	Project     struct {
		ID                int    `json:"id"`
		Name              string `json:"name"`
		PathWithNamespace string `json:"path_with_namespace"`
		GitHTTPURL        string `json:"git_http_url"`
		GitSSHURL         string `json:"git_ssh_url"`
	} `json:"project"`
	Commits []struct {
		ID        string    `json:"id"`
		Message   string    `json:"message"`
		Timestamp time.Time `json:"timestamp"`
		Author    struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		} `json:"author"`
	} `json:"commits"`
}

// NewWebhookManager creates a new webhook manager
func NewWebhookManager(logger *zap.Logger) *WebhookManager {
	return &WebhookManager{
		webhooks: make(map[string]*WebhookConfig),
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}
}

// RegisterWebhook registers a webhook configuration
func (wm *WebhookManager) RegisterWebhook(id string, config *WebhookConfig) error {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	if config.URL == "" {
		return fmt.Errorf("webhook URL is required")
	}

	wm.webhooks[id] = config
	wm.logger.Info("Webhook registered",
		zap.String("id", id),
		zap.String("url", config.URL))

	return nil
}

// UnregisterWebhook removes a webhook configuration
func (wm *WebhookManager) UnregisterWebhook(id string) {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	delete(wm.webhooks, id)
	wm.logger.Info("Webhook unregistered", zap.String("id", id))
}

// SetHandler sets the webhook event handler
func (wm *WebhookManager) SetHandler(handler WebhookHandler) {
	wm.incomingHandler = handler
}

// SendNotification sends a notification to all registered webhooks
func (wm *WebhookManager) SendNotification(update StatusUpdate) {
	wm.mu.RLock()
	webhooks := make(map[string]*WebhookConfig)
	for k, v := range wm.webhooks {
		webhooks[k] = v
	}
	wm.mu.RUnlock()

	// Send to each webhook in parallel
	var wg sync.WaitGroup
	for id, webhook := range webhooks {
		// Check if webhook has events configured
		if len(webhook.Events) == 0 {
			// If no events specified, send all events
		}

		// Check if this event type should be sent
		if len(webhook.Events) > 0 {
			found := false
			for _, event := range webhook.Events {
				if event == string(update.Status) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		wg.Add(1)
		go func(webhookID string, config *WebhookConfig) {
			defer wg.Done()
			if err := wm.sendWebhook(webhookID, config, update); err != nil {
				wm.logger.Error("Failed to send webhook",
					zap.String("webhook_id", webhookID),
					zap.Error(err))
			}
		}(id, webhook)
	}

	wg.Wait()
}

// sendWebhook sends a webhook notification
func (wm *WebhookManager) sendWebhook(webhookID string, config *WebhookConfig, update StatusUpdate) error {
	// Create payload
	payload := map[string]interface{}{
		"event_type":   "pipeline_status_update",
		"timestamp":    time.Now().UTC(),
		"webhook_id":   webhookID,
		"execution_id": update.ExecutionID,
		"stage":        update.Stage,
		"status":       update.Status,
		"message":      update.Message,
		"metadata":     update.Metadata,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Create request
	req, err := http.NewRequest("POST", config.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Eos-Pipeline/1.0")
	req.Header.Set("X-Eos-Event", "pipeline-status-update")
	req.Header.Set("X-Eos-Delivery", fmt.Sprintf("%s-%d", update.ExecutionID, time.Now().Unix()))

	// Add custom headers
	for k, v := range config.Headers {
		req.Header.Set(k, v)
	}

	// Add signature if secret is configured
	if config.Secret != "" {
		signature := wm.generateSignature(body, config.Secret)
		req.Header.Set("X-Eos-Signature", signature)
	}

	// Send request with retries
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}

		resp, err := wm.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			wm.logger.Debug("Webhook sent successfully",
				zap.String("webhook_id", webhookID),
				zap.Int("status_code", resp.StatusCode))
			return nil
		}

		// Read error response
		respBody, _ := io.ReadAll(resp.Body)
		lastErr = fmt.Errorf("webhook returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return fmt.Errorf("webhook failed after 3 attempts: %w", lastErr)
}

// generateSignature generates HMAC-SHA256 signature
func (wm *WebhookManager) generateSignature(payload []byte, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(payload)
	return "sha256=" + hex.EncodeToString(h.Sum(nil))
}

// HandleIncomingWebhook handles incoming webhook requests
func (wm *WebhookManager) HandleIncomingWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		wm.logger.Error("Failed to read webhook body", zap.Error(err))
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	// Extract headers
	headers := make(map[string]string)
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	// Create webhook event
	event := WebhookEvent{
		ID:        fmt.Sprintf("webhook-%d", time.Now().UnixNano()),
		Type:      r.Header.Get("X-GitHub-Event"), // GitHub specific, adapt as needed
		Source:    r.RemoteAddr,
		Timestamp: time.Now(),
		Signature: r.Header.Get("X-Hub-Signature-256"), // GitHub specific
		Headers:   headers,
		Body:      json.RawMessage(body),
		Metadata:  make(map[string]interface{}),
	}

	// Validate signature if present
	if event.Signature != "" {
		// This would validate against registered webhook secrets
		wm.logger.Debug("Webhook signature validation would happen here")
	}

	// Process webhook
	if wm.incomingHandler != nil {
		if err := wm.incomingHandler.HandleWebhook(event); err != nil {
			wm.logger.Error("Failed to handle webhook", zap.Error(err))
			http.Error(w, "Failed to process webhook", http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "accepted",
		"id":     event.ID,
	})
}

// ParseGitHubWebhook parses a GitHub webhook payload
func (wm *WebhookManager) ParseGitHubWebhook(event WebhookEvent) (*GitHubWebhookPayload, error) {
	var payload GitHubWebhookPayload
	if err := json.Unmarshal(event.Body, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse GitHub webhook: %w", err)
	}
	return &payload, nil
}

// ParseGitLabWebhook parses a GitLab webhook payload
func (wm *WebhookManager) ParseGitLabWebhook(event WebhookEvent) (*GitLabWebhookPayload, error) {
	var payload GitLabWebhookPayload
	if err := json.Unmarshal(event.Body, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse GitLab webhook: %w", err)
	}
	return &payload, nil
}

// CreateWebhookServer creates an HTTP server for receiving webhooks
func (wm *WebhookManager) CreateWebhookServer(addr string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/webhook", wm.HandleIncomingWebhook)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	return &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
}

// WebhookTriggerHandler converts webhook events to pipeline triggers
type WebhookTriggerHandler struct {
	engine *PipelineEngine
	logger *zap.Logger
}

// NewWebhookTriggerHandler creates a new webhook trigger handler
func NewWebhookTriggerHandler(engine *PipelineEngine, logger *zap.Logger) *WebhookTriggerHandler {
	return &WebhookTriggerHandler{
		engine: engine,
		logger: logger,
	}
}

// HandleWebhook processes webhook events and triggers pipelines
func (h *WebhookTriggerHandler) HandleWebhook(event WebhookEvent) error {
	h.logger.Info("Processing webhook event",
		zap.String("id", event.ID),
		zap.String("type", event.Type),
		zap.String("source", event.Source))

	// Parse webhook based on type
	switch event.Type {
	case "push", "pull_request": // GitHub events
		payload, err := h.engine.webhookManager.ParseGitHubWebhook(event)
		if err != nil {
			return fmt.Errorf("failed to parse GitHub webhook: %w", err)
		}
		return h.handleGitHubPush(event, payload)

	case "Push Hook", "Merge Request Hook": // GitLab events
		payload, err := h.engine.webhookManager.ParseGitLabWebhook(event)
		if err != nil {
			return fmt.Errorf("failed to parse GitLab webhook: %w", err)
		}
		return h.handleGitLabPush(event, payload)

	default:
		h.logger.Warn("Unknown webhook event type",
			zap.String("type", event.Type))
		return nil
	}
}

// handleGitHubPush handles GitHub push events
func (h *WebhookTriggerHandler) handleGitHubPush(event WebhookEvent, payload *GitHubWebhookPayload) error {
	// Extract branch name from ref
	branch := ""
	if len(payload.Ref) > 11 && payload.Ref[:11] == "refs/heads/" {
		branch = payload.Ref[11:]
	}

	// Create trigger info
	trigger := TriggerInfo{
		Type:    "git_push",
		Source:  "github",
		User:    payload.Pusher.Name,
		Message: payload.HeadCommit.Message,
		Metadata: map[string]string{
			"repository": payload.Repository.FullName,
			"branch":     branch,
			"commit":     payload.HeadCommit.ID,
			"author":     payload.HeadCommit.Author.Name,
		},
		Timestamp: event.Timestamp,
	}

	// TODO: Match webhook to pipeline configuration and trigger
	h.logger.Info("Would trigger pipeline from GitHub webhook",
		zap.String("repository", payload.Repository.FullName),
		zap.String("branch", branch),
		zap.String("commit", payload.HeadCommit.ID),
		zap.Any("trigger", trigger))

	return nil
}

// handleGitLabPush handles GitLab push events
func (h *WebhookTriggerHandler) handleGitLabPush(event WebhookEvent, payload *GitLabWebhookPayload) error {
	// Extract branch name from ref
	branch := ""
	if len(payload.Ref) > 11 && payload.Ref[:11] == "refs/heads/" {
		branch = payload.Ref[11:]
	}

	// Create trigger info
	trigger := TriggerInfo{
		Type:    "git_push",
		Source:  "gitlab",
		User:    payload.UserName,
		Message: "GitLab push event",
		Metadata: map[string]string{
			"repository": payload.Project.PathWithNamespace,
			"branch":     branch,
			"commit":     payload.CheckoutSHA,
			"author":     payload.UserName,
		},
		Timestamp: event.Timestamp,
	}

	// TODO: Match webhook to pipeline configuration and trigger
	h.logger.Info("Would trigger pipeline from GitLab webhook",
		zap.String("repository", payload.Project.PathWithNamespace),
		zap.String("branch", branch),
		zap.String("commit", payload.CheckoutSHA),
		zap.Any("trigger", trigger))

	return nil
}

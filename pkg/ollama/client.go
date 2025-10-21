// Package ollama provides client functions for interacting with Ollama API
// following Eos defensive programming patterns.
//
// Code Monkey Cybersecurity - "Cybersecurity. With humans."
package ollama

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

const (
	// DefaultEndpoint is the default Ollama API endpoint
	DefaultEndpoint = "http://localhost:11434"

	// DefaultDockerEndpoint is the endpoint from inside Docker containers
	DefaultDockerEndpoint = "http://host.docker.internal:11434"

	// DefaultTimeout for Ollama API calls
	DefaultTimeout = 30 * time.Second
)

// Client represents an Ollama API client
type Client struct {
	endpoint string
	http     *http.Client
}

// ModelInfo contains information about an Ollama model
type ModelInfo struct {
	Name       string    `json:"name"`
	ModifiedAt time.Time `json:"modified_at"`
	Size       int64     `json:"size"`
	Digest     string    `json:"digest"`
}

// ModelListResponse is the response from /api/tags
type ModelListResponse struct {
	Models []ModelInfo `json:"models"`
}

// PullProgress represents progress during model pull
type PullProgress struct {
	Status    string `json:"status"`
	Total     int64  `json:"total"`
	Completed int64  `json:"completed"`
	Digest    string `json:"digest,omitempty"`
}

// NewClient creates a new Ollama client
func NewClient(endpoint string) *Client {
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}

	return &Client{
		endpoint: endpoint,
		http: &http.Client{
			Timeout: DefaultTimeout,
		},
	}
}

// HasModel checks if a specific model is available
// Following ASSESS pattern - check before acting
func (c *Client) HasModel(ctx context.Context, modelName string) (bool, error) {
	logger := otelzap.Ctx(ctx)

	models, err := c.ListModels(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to list models: %w", err)
	}

	for _, model := range models {
		// Model names may include tags, e.g., "nomic-embed-text:latest"
		if strings.HasPrefix(model.Name, modelName) {
			logger.Debug("Model found",
				zap.String("model", modelName),
				zap.String("full_name", model.Name))
			return true, nil
		}
	}

	logger.Debug("Model not found", zap.String("model", modelName))
	return false, nil
}

// ListModels retrieves all available models from Ollama
func (c *Client) ListModels(ctx context.Context) ([]ModelInfo, error) {
	url := fmt.Sprintf("%s/api/tags", c.endpoint)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list models: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	var result ModelListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return result.Models, nil
}

// PullModel downloads a model from Ollama
// Following INTERVENE pattern - apply changes
func (c *Client) PullModel(ctx context.Context, modelName string, progressCallback func(PullProgress)) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Pulling Ollama model",
		zap.String("model", modelName),
		zap.String("endpoint", c.endpoint))

	url := fmt.Sprintf("%s/api/pull", c.endpoint)

	reqBody := map[string]string{"name": modelName}
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("failed to pull model: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Stream NDJSON progress responses
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		var progress PullProgress
		if err := json.Unmarshal(scanner.Bytes(), &progress); err != nil {
			logger.Warn("Failed to parse progress", zap.Error(err))
			continue
		}

		// Call progress callback if provided
		if progressCallback != nil {
			progressCallback(progress)
		}

		// Log progress
		if progress.Total > 0 {
			percent := (progress.Completed * 100) / progress.Total
			logger.Debug("Pull progress",
				zap.String("status", progress.Status),
				zap.Int64("percent", percent),
				zap.Int64("completed", progress.Completed),
				zap.Int64("total", progress.Total))
		} else {
			logger.Debug("Pull status", zap.String("status", progress.Status))
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading pull response: %w", err)
	}

	logger.Info("Model pulled successfully", zap.String("model", modelName))
	return nil
}

// TestConnection verifies Ollama is accessible
// Following ASSESS pattern
func (c *Client) TestConnection(ctx context.Context) error {
	url := fmt.Sprintf("%s/api/version", c.endpoint)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("Ollama not accessible at %s: %w", c.endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Ollama API returned status %d", resp.StatusCode)
	}

	return nil
}

// FormatSizeBytes formats byte size in human-readable form
func FormatSizeBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

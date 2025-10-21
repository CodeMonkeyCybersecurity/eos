// Package bionicgpt provides API client for BionicGPT
//
// This client wraps the OpenAI Go SDK (github.com/sashabaranov/go-openai)
// since BionicGPT provides an OpenAI-compatible API.
//
// The client can be used for:
//   - Creating and managing teams
//   - Uploading documents for RAG
//   - Testing multi-tenant isolation
//   - Verifying API functionality
//   - Chat completions
//
// Code Monkey Cybersecurity - "Cybersecurity. With humans."
package bionicgpt

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/sashabaranov/go-openai"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Client provides access to BionicGPT API
type Client struct {
	rc         *eos_io.RuntimeContext
	openaiClient *openai.Client
	baseURL    string
	apiKey     string
}

// ClientConfig contains configuration for BionicGPT API client
type ClientConfig struct {
	BaseURL string // BionicGPT instance URL (e.g., http://localhost:8513)
	APIKey  string // API key for authentication
	Timeout time.Duration
}

// ModelInfo contains information about available models
type ModelInfo struct {
	ID      string
	Object  string
	Created int64
	OwnedBy string
}

// ChatMessage represents a chat message
type ChatMessage struct {
	Role    string // "system", "user", or "assistant"
	Content string
}

// ChatCompletionRequest contains parameters for chat completion
type ChatCompletionRequest struct {
	Model       string
	Messages    []ChatMessage
	Temperature float32
	MaxTokens   int
	Stream      bool
}

// ChatCompletionResponse contains the response from chat completion
type ChatCompletionResponse struct {
	ID      string
	Object  string
	Created int64
	Model   string
	Choices []ChatChoice
	Usage   ChatUsage
}

// ChatChoice represents a single completion choice
type ChatChoice struct {
	Index        int
	Message      ChatMessage
	FinishReason string
}

// ChatUsage contains token usage information
type ChatUsage struct {
	PromptTokens     int
	CompletionTokens int
	TotalTokens      int
}

// NewClient creates a new BionicGPT API client
func NewClient(rc *eos_io.RuntimeContext, config ClientConfig) (*Client, error) {
	logger := otelzap.Ctx(rc.Ctx)

	if config.BaseURL == "" {
		return nil, fmt.Errorf("BaseURL is required")
	}
	if config.APIKey == "" {
		return nil, fmt.Errorf("APIKey is required")
	}

	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	// Create OpenAI client configuration
	openaiConfig := openai.DefaultConfig(config.APIKey)
	openaiConfig.BaseURL = fmt.Sprintf("%s/v1", config.BaseURL)
	openaiConfig.HTTPClient = &http.Client{
		Timeout: config.Timeout,
	}

	// Create OpenAI client
	openaiClient := openai.NewClientWithConfig(openaiConfig)

	logger.Info("BionicGPT API client created",
		zap.String("base_url", config.BaseURL))

	return &Client{
		rc:           rc,
		openaiClient: openaiClient,
		baseURL:      config.BaseURL,
		apiKey:       config.APIKey,
	}, nil
}

// ListModels retrieves available models from BionicGPT
func (c *Client) ListModels(ctx context.Context) ([]ModelInfo, error) {
	logger := otelzap.Ctx(ctx)
	logger.Debug("Listing available models")

	response, err := c.openaiClient.ListModels(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list models: %w", err)
	}

	models := make([]ModelInfo, len(response.Models))
	for i, model := range response.Models {
		models[i] = ModelInfo{
			ID:      model.ID,
			Object:  model.Object,
			Created: model.CreatedAt,
			OwnedBy: model.OwnedBy,
		}
	}

	logger.Info("Models retrieved successfully", zap.Int("count", len(models)))
	return models, nil
}

// ChatCompletion sends a chat completion request to BionicGPT
func (c *Client) ChatCompletion(ctx context.Context, req ChatCompletionRequest) (*ChatCompletionResponse, error) {
	logger := otelzap.Ctx(ctx)
	logger.Debug("Sending chat completion request",
		zap.String("model", req.Model),
		zap.Int("message_count", len(req.Messages)))

	// Convert our messages to OpenAI format
	openaiMessages := make([]openai.ChatCompletionMessage, len(req.Messages))
	for i, msg := range req.Messages {
		openaiMessages[i] = openai.ChatCompletionMessage{
			Role:    msg.Role,
			Content: msg.Content,
		}
	}

	// Create OpenAI request
	openaiReq := openai.ChatCompletionRequest{
		Model:       req.Model,
		Messages:    openaiMessages,
		Temperature: req.Temperature,
		MaxTokens:   req.MaxTokens,
		Stream:      req.Stream,
	}

	// Send request
	response, err := c.openaiClient.CreateChatCompletion(ctx, openaiReq)
	if err != nil {
		return nil, fmt.Errorf("chat completion failed: %w", err)
	}

	// Convert response
	choices := make([]ChatChoice, len(response.Choices))
	for i, choice := range response.Choices {
		choices[i] = ChatChoice{
			Index: choice.Index,
			Message: ChatMessage{
				Role:    choice.Message.Role,
				Content: choice.Message.Content,
			},
			FinishReason: string(choice.FinishReason),
		}
	}

	result := &ChatCompletionResponse{
		ID:      response.ID,
		Object:  response.Object,
		Created: response.Created,
		Model:   response.Model,
		Choices: choices,
		Usage: ChatUsage{
			PromptTokens:     response.Usage.PromptTokens,
			CompletionTokens: response.Usage.CompletionTokens,
			TotalTokens:      response.Usage.TotalTokens,
		},
	}

	logger.Info("Chat completion successful",
		zap.String("model", result.Model),
		zap.Int("total_tokens", result.Usage.TotalTokens))

	return result, nil
}

// Ping tests connectivity to BionicGPT API
func (c *Client) Ping(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)
	logger.Debug("Pinging BionicGPT API")

	// Try to list models as a health check
	_, err := c.ListModels(ctx)
	if err != nil {
		return fmt.Errorf("API not responding: %w", err)
	}

	logger.Info("BionicGPT API is responding")
	return nil
}

// TestChatCompletion performs a simple test chat completion
func (c *Client) TestChatCompletion(ctx context.Context, model string) (*ChatCompletionResponse, error) {
	logger := otelzap.Ctx(ctx)
	logger.Info("Testing chat completion", zap.String("model", model))

	req := ChatCompletionRequest{
		Model: model,
		Messages: []ChatMessage{
			{
				Role:    "user",
				Content: "Say 'Hello from BionicGPT' if you can read this message.",
			},
		},
		Temperature: 0.7,
		MaxTokens:   50,
	}

	response, err := c.ChatCompletion(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("test chat completion failed: %w", err)
	}

	logger.Info("Test chat completion successful",
		zap.String("response", response.Choices[0].Message.Content))

	return response, nil
}

// ValidateAPIAccess performs comprehensive API validation
func (c *Client) ValidateAPIAccess(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)
	logger.Info("Validating BionicGPT API access")

	// Step 1: Test connectivity
	if err := c.Ping(ctx); err != nil {
		return fmt.Errorf("connectivity test failed: %w", err)
	}

	// Step 2: List models
	models, err := c.ListModels(ctx)
	if err != nil {
		return fmt.Errorf("failed to list models: %w", err)
	}

	if len(models) == 0 {
		return fmt.Errorf("no models available")
	}

	logger.Info("Found available models", zap.Int("count", len(models)))

	// Step 3: Test chat completion with first available model
	_, err = c.TestChatCompletion(ctx, models[0].ID)
	if err != nil {
		return fmt.Errorf("chat completion test failed: %w", err)
	}

	logger.Info("API validation successful")
	return nil
}

// GetAvailableModel returns the first available model ID
func (c *Client) GetAvailableModel(ctx context.Context) (string, error) {
	models, err := c.ListModels(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to list models: %w", err)
	}

	if len(models) == 0 {
		return "", fmt.Errorf("no models available")
	}

	return models[0].ID, nil
}

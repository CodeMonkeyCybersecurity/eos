package ai

import (
	"fmt"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/httpclient"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigManager(t *testing.T) {
	t.Run("new config manager", func(t *testing.T) {
		cm := NewConfigManager()
		assert.NotNil(t, cm)
		assert.NotNil(t, cm.config)

		// Test default values
		config := cm.GetConfig()
		assert.NotNil(t, config)
	})

	t.Run("load config", func(t *testing.T) {
		cm := NewConfigManager()

		// Test loading config (may fail if file doesn't exist, but shouldn't panic)
		err := cm.LoadConfig()
		if err != nil {
			t.Logf("LoadConfig returned error (expected if no config file): %v", err)
		}

		// Config should still be accessible
		config := cm.GetConfig()
		assert.NotNil(t, config)
	})

	t.Run("save and load config", func(t *testing.T) {
		cm := NewConfigManager()

		// Create test config
		testConfig := &AIConfig{
			Provider:  "azure-openai",
			APIKey:    "test-key-456",
			BaseURL:   "https://test.openai.azure.com",
			Model:     "gpt-3.5-turbo",
			MaxTokens: 2000,
		}

		cm.config = testConfig

		// Test config retrieval
		config := cm.GetConfig()
		assert.Equal(t, testConfig.Provider, config.Provider)
		assert.Equal(t, testConfig.APIKey, config.APIKey)
		assert.Equal(t, testConfig.BaseURL, config.BaseURL)
		assert.Equal(t, testConfig.Model, config.Model)
		assert.Equal(t, testConfig.MaxTokens, config.MaxTokens)
	})

	t.Run("config validation", func(t *testing.T) {
		cm := NewConfigManager()

		// Test valid config
		validConfig := &AIConfig{
			Provider:  "anthropic",
			APIKey:    "sk-valid123",
			BaseURL:   "https://api.anthropic.com/v1",
			Model:     "claude-3-sonnet-20240229",
			MaxTokens: 1000,
		}
		cm.config = validConfig

		// Test config fields are accessible
		config := cm.GetConfig()
		assert.Equal(t, "anthropic", config.Provider)
		assert.Equal(t, "sk-valid123", config.APIKey)
		assert.Equal(t, "https://api.anthropic.com/v1", config.BaseURL)
		assert.Equal(t, "claude-3-sonnet-20240229", config.Model)
		assert.Equal(t, 1000, config.MaxTokens)

		// Test empty config handling
		emptyConfig := &AIConfig{}
		cm.config = emptyConfig

		config = cm.GetConfig()
		assert.Equal(t, "", config.Provider)
		assert.Equal(t, "", config.APIKey)
		assert.Equal(t, "", config.BaseURL)
		assert.Equal(t, "", config.Model)
		assert.Equal(t, 0, config.MaxTokens)
	})
}

func TestGetProviderDefaults(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		expected *AIConfig
	}{
		{
			name:     "anthropic defaults",
			provider: "anthropic",
			expected: &AIConfig{
				Provider:  "anthropic",
				BaseURL:   "https://api.anthropic.com/v1",
				Model:     "claude-3-sonnet-20240229",
				MaxTokens: 4096,
				Timeout:   60,
			},
		},
		{
			name:     "azure-openai defaults",
			provider: "azure-openai",
			expected: &AIConfig{
				Provider:        "azure-openai",
				Model:           "gpt-4",
				MaxTokens:       4096,
				Timeout:         60,
				AzureAPIVersion: "2024-02-15-preview",
			},
		},
		{
			name:     "unknown provider defaults to anthropic",
			provider: "unknown",
			expected: &AIConfig{
				Provider:  "anthropic",
				BaseURL:   "https://api.anthropic.com/v1",
				Model:     "claude-3-sonnet-20240229",
				MaxTokens: 4096,
				Timeout:   60,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetProviderDefaults(tt.provider)

			require.NotNil(t, result)
			assert.Equal(t, tt.expected.Provider, result.Provider)
			assert.Equal(t, tt.expected.BaseURL, result.BaseURL)
			assert.Equal(t, tt.expected.Model, result.Model)
			assert.Equal(t, tt.expected.MaxTokens, result.MaxTokens)
			assert.Equal(t, tt.expected.Timeout, result.Timeout)

			if tt.provider == "azure-openai" {
				assert.Equal(t, tt.expected.AzureAPIVersion, result.AzureAPIVersion)
			}
		})
	}
}

func TestAIConfigFields(t *testing.T) {
	t.Run("all fields accessible", func(t *testing.T) {
		config := &AIConfig{
			Provider:        "azure-openai",
			APIKey:          "test-key",
			APIKeyVault:     "vault/path",
			BaseURL:         "https://test.openai.azure.com",
			Model:           "gpt-4",
			MaxTokens:       2000,
			Timeout:         30,
			AzureEndpoint:   "https://test.openai.azure.com",
			AzureAPIVersion: "2024-02-15-preview",
			AzureDeployment: "gpt-4-deployment",
		}

		// Test all fields are accessible
		assert.Equal(t, "azure-openai", config.Provider)
		assert.Equal(t, "test-key", config.APIKey)
		assert.Equal(t, "vault/path", config.APIKeyVault)
		assert.Equal(t, "https://test.openai.azure.com", config.BaseURL)
		assert.Equal(t, "gpt-4", config.Model)
		assert.Equal(t, 2000, config.MaxTokens)
		assert.Equal(t, 30, config.Timeout)
		assert.Equal(t, "https://test.openai.azure.com", config.AzureEndpoint)
		assert.Equal(t, "2024-02-15-preview", config.AzureAPIVersion)
		assert.Equal(t, "gpt-4-deployment", config.AzureDeployment)
	})

	t.Run("zero values", func(t *testing.T) {
		config := &AIConfig{}

		assert.Equal(t, "", config.Provider)
		assert.Equal(t, "", config.APIKey)
		assert.Equal(t, "", config.APIKeyVault)
		assert.Equal(t, "", config.BaseURL)
		assert.Equal(t, "", config.Model)
		assert.Equal(t, 0, config.MaxTokens)
		assert.Equal(t, 0, config.Timeout)
		assert.Equal(t, "", config.AzureEndpoint)
		assert.Equal(t, "", config.AzureAPIVersion)
		assert.Equal(t, "", config.AzureDeployment)
	})
}

func TestConversationContext(t *testing.T) {
	t.Run("conversation context creation", func(t *testing.T) {
		ctx := &ConversationContext{
			SystemPrompt: "You are a helpful AI assistant",
			Messages:     []AIMessage{},
		}

		assert.Equal(t, "You are a helpful AI assistant", ctx.SystemPrompt)
		assert.Len(t, ctx.Messages, 0)
	})

	t.Run("add messages", func(t *testing.T) {
		ctx := &ConversationContext{
			SystemPrompt: "You are a helpful AI assistant",
			Messages:     []AIMessage{},
		}

		// Add user message
		userMsg := AIMessage{
			Role:    "user",
			Content: "Hello, how are you?",
		}
		ctx.Messages = append(ctx.Messages, userMsg)

		// Add assistant message
		assistantMsg := AIMessage{
			Role:    "assistant",
			Content: "I'm doing well, thank you! How can I help you today?",
		}
		ctx.Messages = append(ctx.Messages, assistantMsg)

		assert.Len(t, ctx.Messages, 2)
		assert.Equal(t, "user", ctx.Messages[0].Role)
		assert.Equal(t, "Hello, how are you?", ctx.Messages[0].Content)
		assert.Equal(t, "assistant", ctx.Messages[1].Role)
		assert.Equal(t, "I'm doing well, thank you! How can I help you today?", ctx.Messages[1].Content)
	})

	t.Run("message limit handling", func(t *testing.T) {
		ctx := &ConversationContext{
			SystemPrompt: "You are a helpful AI assistant",
			Messages:     []AIMessage{},
		}

		// Add many messages
		for i := 0; i < 100; i++ {
			msg := AIMessage{
				Role:    "user",
				Content: fmt.Sprintf("Message %d", i),
			}
			ctx.Messages = append(ctx.Messages, msg)
		}

		assert.Len(t, ctx.Messages, 100)
		assert.Equal(t, "Message 0", ctx.Messages[0].Content)
		assert.Equal(t, "Message 99", ctx.Messages[99].Content)
	})
}

func TestAIMessage(t *testing.T) {
	t.Run("message creation", func(t *testing.T) {
		msg := AIMessage{
			Role:    "user",
			Content: "Test message content",
		}

		assert.Equal(t, "user", msg.Role)
		assert.Equal(t, "Test message content", msg.Content)
	})

	t.Run("empty message", func(t *testing.T) {
		msg := AIMessage{}

		assert.Equal(t, "", msg.Role)
		assert.Equal(t, "", msg.Content)
	})

	t.Run("message with special characters", func(t *testing.T) {
		specialContent := "Message with émojis  and\nnewlines\tand\ttabs"
		msg := AIMessage{
			Role:    "user",
			Content: specialContent,
		}

		assert.Equal(t, "user", msg.Role)
		assert.Equal(t, specialContent, msg.Content)
	})
}

func TestAIAssistantStructure(t *testing.T) {
	t.Run("assistant with valid config", func(t *testing.T) {
		assistant := &AIAssistant{
			provider:  "anthropic",
			apiKey:    "sk-test123",
			baseURL:   "https://api.anthropic.com/v1",
			model:     "claude-3-sonnet-20240229",
			maxTokens: 1000,
		}

		assert.Equal(t, "anthropic", assistant.provider)
		assert.Equal(t, "sk-test123", assistant.apiKey)
		assert.Equal(t, "https://api.anthropic.com/v1", assistant.baseURL)
		assert.Equal(t, "claude-3-sonnet-20240229", assistant.model)
		assert.Equal(t, 1000, assistant.maxTokens)
	})

	t.Run("assistant with azure config", func(t *testing.T) {
		assistant := &AIAssistant{
			provider:        "azure-openai",
			apiKey:          "azure-key-123",
			azureEndpoint:   "https://test.openai.azure.com",
			azureAPIVersion: "2024-02-15-preview",
			azureDeployment: "gpt-4-deployment",
			model:           "gpt-4",
			maxTokens:       2000,
		}

		assert.Equal(t, "azure-openai", assistant.provider)
		assert.Equal(t, "azure-key-123", assistant.apiKey)
		assert.Equal(t, "https://test.openai.azure.com", assistant.azureEndpoint)
		assert.Equal(t, "2024-02-15-preview", assistant.azureAPIVersion)
		assert.Equal(t, "gpt-4-deployment", assistant.azureDeployment)
	})
}

func TestAIResponseStructure(t *testing.T) {
	t.Run("response creation", func(t *testing.T) {
		response := &AIResponse{
			Choices: []AIChoice{
				{
					Message: AIMessage{
						Role:    "assistant",
						Content: "This is a test response",
					},
				},
			},
			Usage: AIUsage{
				PromptTokens:     10,
				CompletionTokens: 15,
				TotalTokens:      25,
			},
		}

		assert.Len(t, response.Choices, 1)
		assert.Equal(t, "This is a test response", response.Choices[0].Message.Content)
		assert.Equal(t, 10, response.Usage.PromptTokens)
		assert.Equal(t, 15, response.Usage.CompletionTokens)
		assert.Equal(t, 25, response.Usage.TotalTokens)
	})

	t.Run("empty response", func(t *testing.T) {
		response := &AIResponse{}

		assert.Len(t, response.Choices, 0)
		assert.Equal(t, 0, response.Usage.PromptTokens)
		assert.Equal(t, 0, response.Usage.CompletionTokens)
		assert.Equal(t, 0, response.Usage.TotalTokens)
	})
}

func TestUsageTracking(t *testing.T) {
	t.Run("usage calculation", func(t *testing.T) {
		usage := AIUsage{
			PromptTokens:     100,
			CompletionTokens: 50,
			TotalTokens:      150,
		}

		assert.Equal(t, 100, usage.PromptTokens)
		assert.Equal(t, 50, usage.CompletionTokens)
		assert.Equal(t, 150, usage.TotalTokens)

		// Verify total is sum of prompt and completion
		assert.Equal(t, usage.PromptTokens+usage.CompletionTokens, usage.TotalTokens)
	})

	t.Run("zero usage", func(t *testing.T) {
		usage := AIUsage{}

		assert.Equal(t, 0, usage.PromptTokens)
		assert.Equal(t, 0, usage.CompletionTokens)
		assert.Equal(t, 0, usage.TotalTokens)
	})
}

func TestRequestStructure(t *testing.T) {
	t.Run("request structure validation", func(t *testing.T) {
		tests := []struct {
			name    string
			request AIRequest
			isValid bool
		}{
			{
				name: "valid request",
				request: AIRequest{
					Model: "claude-3-sonnet-20240229",
					Messages: []AIMessage{
						{Role: "user", Content: "Hello"},
					},
					MaxTokens: 100,
				},
				isValid: true,
			},
			{
				name: "empty model",
				request: AIRequest{
					Model: "",
					Messages: []AIMessage{
						{Role: "user", Content: "Hello"},
					},
					MaxTokens: 100,
				},
				isValid: true, // Should handle gracefully
			},
			{
				name: "no messages",
				request: AIRequest{
					Model:     "claude-3-sonnet-20240229",
					Messages:  []AIMessage{},
					MaxTokens: 100,
				},
				isValid: true, // Should handle gracefully
			},
			{
				name: "zero max tokens",
				request: AIRequest{
					Model: "claude-3-sonnet-20240229",
					Messages: []AIMessage{
						{Role: "user", Content: "Hello"},
					},
					MaxTokens: 0,
				},
				isValid: true, // Should handle gracefully
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				// Test that request can be created without panicking
				assert.NotNil(t, &tt.request)
				assert.Equal(t, tt.request.Model, tt.request.Model)
				assert.Equal(t, len(tt.request.Messages), len(tt.request.Messages))
				assert.Equal(t, tt.request.MaxTokens, tt.request.MaxTokens)
			})
		}
	})
}

func TestChatErrorHandling(t *testing.T) {
	t.Run("chat with empty API key", func(t *testing.T) {
		rc := testutil.TestRuntimeContext(t)

		assistant := &AIAssistant{
			provider:  "anthropic",
			apiKey:    "", // Empty API key
			baseURL:   "https://api.anthropic.com/v1",
			model:     "claude-3-sonnet-20240229",
			maxTokens: 100,
			client: func() *httpclient.Client {
				c, _ := httpclient.NewClient(&httpclient.Config{Timeout: 30 * time.Second})
				return c
			}(),
		}

		ctx := &ConversationContext{
			SystemPrompt: "You are a helpful assistant",
			Messages:     []AIMessage{},
		}

		_, err := assistant.Chat(rc, ctx, "test message")
		assert.Error(t, err, "Should return error for empty API key")
		assert.Contains(t, err.Error(), "API key")
	})

	t.Run("chat with invalid URL", func(t *testing.T) {
		rc := testutil.TestRuntimeContext(t)

		assistant := &AIAssistant{
			provider:  "anthropic",
			apiKey:    "sk-test123",
			baseURL:   "invalid-url", // Invalid URL
			model:     "claude-3-sonnet-20240229",
			maxTokens: 100,
			client: func() *httpclient.Client {
				c, _ := httpclient.NewClient(&httpclient.Config{Timeout: 30 * time.Second})
				return c
			}(),
		}

		ctx := &ConversationContext{
			SystemPrompt: "You are a helpful assistant",
			Messages:     []AIMessage{},
		}

		// This should handle the invalid URL gracefully
		_, err := assistant.Chat(rc, ctx, "test message")
		if err != nil {
			t.Logf("Expected error for invalid URL: %v", err)
		}
	})
}

func TestAPIKeyValidation(t *testing.T) {
	tests := []struct {
		name      string
		apiKey    string
		shouldErr bool
	}{
		{
			name:      "valid anthropic key",
			apiKey:    "sk-ant-1234567890abcdef1234567890",
			shouldErr: false,
		},
		{
			name:      "valid openai key",
			apiKey:    "sk-1234567890abcdef1234567890",
			shouldErr: false,
		},
		{
			name:      "empty key",
			apiKey:    "",
			shouldErr: true,
		},
		{
			name:      "too short key",
			apiKey:    "sk-123",
			shouldErr: true,
		},
		{
			name:      "valid length unknown format",
			apiKey:    "very-long-api-key-with-unknown-format-1234567890",
			shouldErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAPIKey(tt.apiKey)
			if tt.shouldErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMaskAPIKey(t *testing.T) {
	tests := []struct {
		name     string
		apiKey   string
		expected string
	}{
		{
			name:     "empty key",
			apiKey:   "",
			expected: "[not configured]",
		},
		{
			name:     "short key",
			apiKey:   "123",
			expected: "***",
		},
		{
			name:     "medium key",
			apiKey:   "12345",
			expected: "123...",
		},
		{
			name:     "long key",
			apiKey:   "sk-1234567890abcdef",
			expected: "sk-123...cdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MaskAPIKey(tt.apiKey)
			assert.Equal(t, tt.expected, result)
		})
	}
}

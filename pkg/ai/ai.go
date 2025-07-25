// pkg/ai/ai.go

package ai

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/httpclient"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// AIAssistant represents the AI assistant for infrastructure management
type AIAssistant struct {
	provider  string
	apiKey    string
	baseURL   string
	model     string
	client    *httpclient.Client
	maxTokens int

	// Azure OpenAI specific fields
	azureEndpoint   string
	azureAPIVersion string
	azureDeployment string
}

// AIRequest represents a request to the AI service
type AIRequest struct {
	Model     string      `json:"model"`
	Messages  []AIMessage `json:"messages"`
	MaxTokens int         `json:"max_tokens"`
	Stream    bool        `json:"stream"`
}

// AIMessage represents a message in the AI conversation
type AIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// AIResponse represents the response from the AI service
type AIResponse struct {
	ID      string     `json:"id"`
	Object  string     `json:"object"`
	Created int64      `json:"created"`
	Model   string     `json:"model"`
	Choices []AIChoice `json:"choices"`
	Usage   AIUsage    `json:"usage"`
}

// AIChoice represents a choice in the AI response
type AIChoice struct {
	Index        int       `json:"index"`
	Message      AIMessage `json:"message"`
	FinishReason string    `json:"finish_reason"`
}

// AIUsage represents token usage information
type AIUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// ConversationContext holds context for AI conversations
type ConversationContext struct {
	SystemPrompt   string
	Environment    *EnvironmentContext
	ConversationID string
	Messages       []AIMessage
	LastResponse   *AIResponse
	ActiveSession  bool
}

// EnvironmentContext holds information about the current environment
type EnvironmentContext struct {
	WorkingDirectory string
	FileSystem       *FileSystemContext
	Services         *ServicesContext
	Infrastructure   *InfrastructureContext
	Logs             *LogContext
	SystemInfo       *SystemInfo
}

// FileSystemContext holds file system information
type FileSystemContext struct {
	RecentFiles    []FileInfo
	ConfigFiles    []FileInfo
	ComposeFiles   []FileInfo
	TerraformFiles []FileInfo
	DirectoryTree  map[string][]string
}

// ServicesContext holds information about running services
type ServicesContext struct {
	DockerContainers []ContainerInfo
	SystemdServices  []ServiceInfo
	Processes        []ProcessInfo
	NetworkPorts     []PortInfo
}

// InfrastructureContext holds infrastructure state information
type InfrastructureContext struct {
	TerraformState   *TerraformStateInfo
	VaultStatus      *VaultStatusInfo
	ConsulStatus     *ConsulStatusInfo
	KubernetesStatus *K8sStatusInfo
}

// LogContext holds recent log information
type LogContext struct {
	SystemLogs   []LogEntry
	ServiceLogs  []LogEntry
	ErrorLogs    []LogEntry
	RecentErrors []LogEntry
}

// SystemInfo holds system information
type SystemInfo struct {
	OS           string
	Architecture string
	Hostname     string
	Uptime       string
	LoadAverage  string
	Memory       string
	Disk         string
}

// FileInfo represents file information
type FileInfo struct {
	Path        string
	Size        int64
	ModTime     time.Time
	IsDirectory bool
	ContentType string
	Excerpt     string
}

// ContainerInfo represents Docker container information
type ContainerInfo struct {
	ID     string
	Name   string
	Image  string
	Status string
	Ports  []string
	Health string
}

// ServiceInfo represents systemd service information
type ServiceInfo struct {
	Name   string
	Status string
	Active bool
	Loaded bool
}

// ProcessInfo represents process information
type ProcessInfo struct {
	PID     int
	Name    string
	CPU     float64
	Memory  float64
	Command string
}

// PortInfo represents network port information
type PortInfo struct {
	Port     int
	Protocol string
	Service  string
	Status   string
}

// TerraformStateInfo represents Terraform state
type TerraformStateInfo struct {
	Resources []string
	Outputs   map[string]string
	Backend   string
	Version   string
}

// VaultStatusInfo represents Vault status
type VaultStatusInfo struct {
	Sealed      bool
	Initialized bool
	Version     string
	ClusterName string
}

// ConsulStatusInfo represents Consul status
type ConsulStatusInfo struct {
	Leader     string
	Peers      []string
	Services   []string
	Datacenter string
}

// K8sStatusInfo represents Kubernetes status
type K8sStatusInfo struct {
	Nodes     []string
	Pods      []string
	Services  []string
	Namespace string
}

// LogEntry represents a log entry
type LogEntry struct {
	Timestamp time.Time
	Level     string
	Service   string
	Message   string
	Source    string
}

// NewAIAssistant creates a new AI assistant instance
func NewAIAssistant(rc *eos_io.RuntimeContext) (*AIAssistant, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Load configuration
	configManager := NewConfigManager()
	if err := configManager.LoadConfig(); err != nil {
		logger.Warn("Failed to load AI config", zap.Error(err))
	}

	// Get API key
	apiKey, err := configManager.GetAPIKey(rc)
	if err != nil {
		// Don't fail here, let Chat method handle the error
		logger.Debug("API key not available", zap.Error(err))
		apiKey = ""
	}

	config := configManager.GetConfig()

	// Determine provider
	provider := config.Provider
	if provider == "" {
		provider = "anthropic" // Default to Anthropic
	}

	var baseURL, model string
	var azureEndpoint, azureAPIVersion, azureDeployment string

	// Configure based on provider
	if provider == "azure-openai" {
		// Azure OpenAI configuration
		azureEndpoint = config.AzureEndpoint
		if envEndpoint := os.Getenv("AZURE_OPENAI_ENDPOINT"); envEndpoint != "" {
			azureEndpoint = envEndpoint
		}

		azureAPIVersion = config.AzureAPIVersion
		if azureAPIVersion == "" {
			azureAPIVersion = "2024-02-15-preview"
		}
		if envVersion := os.Getenv("AZURE_OPENAI_API_VERSION"); envVersion != "" {
			azureAPIVersion = envVersion
		}

		azureDeployment = config.AzureDeployment
		if envDeployment := os.Getenv("AZURE_OPENAI_DEPLOYMENT"); envDeployment != "" {
			azureDeployment = envDeployment
		}

		model = config.Model
		if model == "" {
			model = "gpt-4"
		}
		if envModel := os.Getenv("AZURE_OPENAI_MODEL"); envModel != "" {
			model = envModel
		}

		// Construct Azure OpenAI URL
		if azureEndpoint != "" && azureDeployment != "" {
			baseURL = fmt.Sprintf("%s/openai/deployments/%s", azureEndpoint, azureDeployment)
		}
	} else {
		// Anthropic configuration
		baseURL = config.BaseURL
		if baseURL == "" {
			baseURL = "https://api.anthropic.com/v1"
		}
		if envURL := os.Getenv("ANTHROPIC_BASE_URL"); envURL != "" {
			baseURL = envURL
		}

		model = config.Model
		if model == "" {
			model = "claude-3-sonnet-20240229"
		}
		if envModel := os.Getenv("ANTHROPIC_MODEL"); envModel != "" {
			model = envModel
		}
	}

	maxTokens := config.MaxTokens
	if maxTokens == 0 {
		maxTokens = 4096
	}

	timeout := time.Duration(config.Timeout) * time.Second
	if timeout == 0 {
		timeout = 60 * time.Second
	}

	// Create enhanced HTTP client using unified framework
	client, err := httpclient.MigrateFromLLMClient(apiKey, string(provider))
	if err != nil {
		// Fallback to default client if migration fails
		client, _ = httpclient.NewClient(httpclient.DefaultConfig())
	}

	return &AIAssistant{
		provider:        provider,
		apiKey:          apiKey,
		baseURL:         baseURL,
		model:           model,
		azureEndpoint:   azureEndpoint,
		azureAPIVersion: azureAPIVersion,
		azureDeployment: azureDeployment,
		client:          client,
		maxTokens:       maxTokens,
	}, nil
}

// Chat sends a message to the AI and returns the response
func (ai *AIAssistant) Chat(rc *eos_io.RuntimeContext, ctx *ConversationContext, userMessage string) (*AIResponse, error) {
	logger := otelzap.Ctx(rc.Ctx)

	if ai.apiKey == "" {
		return nil, fmt.Errorf("AI API key not configured. Run 'eos ai configure' to set it up")
	}

	// Build conversation messages
	messages := []AIMessage{}

	// Add system prompt
	if ctx.SystemPrompt != "" {
		messages = append(messages, AIMessage{
			Role:    "system",
			Content: ctx.SystemPrompt,
		})
	}

	// Add conversation history
	messages = append(messages, ctx.Messages...)

	// Add current user message
	messages = append(messages, AIMessage{
		Role:    "user",
		Content: userMessage,
	})

	// Create request
	request := AIRequest{
		Model:     ai.model,
		Messages:  messages,
		MaxTokens: ai.maxTokens,
		Stream:    false,
	}

	// Send request
	response, err := ai.sendRequest(rc, request)
	if err != nil {
		logger.Error("Failed to send AI request", zap.Error(err))
		return nil, fmt.Errorf("AI request failed: %w", err)
	}

	// Update conversation context
	ctx.Messages = append(ctx.Messages, AIMessage{
		Role:    "user",
		Content: userMessage,
	})

	if len(response.Choices) > 0 {
		ctx.Messages = append(ctx.Messages, response.Choices[0].Message)
		ctx.LastResponse = response
	}

	logger.Info("AI request completed",
		zap.String("model", response.Model),
		zap.Int("prompt_tokens", response.Usage.PromptTokens),
		zap.Int("completion_tokens", response.Usage.CompletionTokens))

	return response, nil
}

// sendRequest sends the HTTP request to the AI service
func (ai *AIAssistant) sendRequest(rc *eos_io.RuntimeContext, request AIRequest) (*AIResponse, error) {
	var requestBody []byte
	var err error
	var url string

	if ai.provider == "azure-openai" {
		// Azure OpenAI uses a different request format
		azureRequest := map[string]any{
			"messages":    request.Messages,
			"max_tokens":  request.MaxTokens,
			"temperature": 0.7,
			"stream":      false,
		}
		requestBody, err = json.Marshal(azureRequest)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Azure request: %w", err)
		}

		// Azure OpenAI URL format
		url = fmt.Sprintf("%s/chat/completions?api-version=%s", ai.baseURL, ai.azureAPIVersion)
	} else {
		// Anthropic request format
		requestBody, err = json.Marshal(request)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request: %w", err)
		}

		url = ai.baseURL + "/messages"
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(rc.Ctx, "POST", url, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers based on provider
	req.Header.Set("Content-Type", "application/json")
	if ai.provider == "azure-openai" {
		req.Header.Set("api-key", ai.apiKey)
	} else {
		req.Header.Set("Authorization", "Bearer "+ai.apiKey)
		req.Header.Set("anthropic-version", "2023-06-01")
	}

	// Send request using unified client
	resp, err := ai.client.DoWithContext(rc.Ctx, req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log silently for HTTP response cleanup
			_ = err
		}
	}()

	// Read response
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check for HTTP errors
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(responseBody))
	}

	// Parse response based on provider
	var aiResponse AIResponse
	if ai.provider == "azure-openai" {
		// Azure OpenAI response format is compatible with OpenAI format
		if err := json.Unmarshal(responseBody, &aiResponse); err != nil {
			return nil, fmt.Errorf("failed to unmarshal Azure response: %w", err)
		}
	} else {
		// Anthropic response format
		if err := json.Unmarshal(responseBody, &aiResponse); err != nil {
			return nil, fmt.Errorf("failed to unmarshal response: %w", err)
		}
	}

	return &aiResponse, nil
}

// NewConversationContext creates a new conversation context
func NewConversationContext(systemPrompt string) *ConversationContext {
	return &ConversationContext{
		SystemPrompt:   systemPrompt,
		ConversationID: generateConversationID(),
		Messages:       []AIMessage{},
		ActiveSession:  true,
	}
}

// generateConversationID generates a unique conversation ID
func generateConversationID() string {
	// Generate random bytes for uniqueness
	randomBytes := make([]byte, 8)
	if _, err := rand.Read(randomBytes); err != nil {
		// Fallback to timestamp if random generation fails
		return fmt.Sprintf("eos-ai-%d", time.Now().UnixNano())
	}

	// Combine timestamp and random bytes for uniqueness
	timestamp := time.Now().Unix()
	randomHex := hex.EncodeToString(randomBytes)
	return fmt.Sprintf("eos-ai-%d-%s", timestamp, randomHex)
}

// GetInfrastructureSystemPrompt returns the system prompt for infrastructure management
func GetInfrastructureSystemPrompt() string {
	return `You are an advanced infrastructure AI assistant integrated into Eos, a comprehensive infrastructure management tool similar to Google's Borg system. 

Your capabilities include:
- Analyzing and managing Terraform infrastructure as code
- Working with HashiCorp Vault for secrets management
- Managing Consul for service discovery and configuration
- Understanding Docker Compose files and container orchestration
- Analyzing system logs and troubleshooting issues
- Suggesting infrastructure improvements and fixes
- Implementing changes to configuration files
- Monitoring system health and performance

You have access to the current environment context including:
- File system structure and contents
- Running services and their status
- Infrastructure state (Terraform, Vault, Consul)
- Recent logs and error messages
- System performance metrics

When helping users:
1. Always analyze the provided environment context first
2. Ask clarifying questions if needed
3. Provide specific, actionable recommendations
4. Explain the reasoning behind your suggestions
5. Offer to implement changes when appropriate
6. Consider security and best practices
7. Be prepared to iteratively improve solutions based on feedback

You should be conversational, helpful, and focus on practical solutions that improve infrastructure reliability and manageability.`
}

// BuildEnvironmentPrompt creates a detailed prompt with environment context
func BuildEnvironmentPrompt(ctx *ConversationContext, userQuery string) string {
	var prompt strings.Builder

	prompt.WriteString("=== CURRENT ENVIRONMENT CONTEXT ===\n\n")

	if ctx.Environment != nil {
		// Add working directory
		if ctx.Environment.WorkingDirectory != "" {
			prompt.WriteString(fmt.Sprintf("Working Directory: %s\n\n", ctx.Environment.WorkingDirectory))
		}

		// Add file system context
		if ctx.Environment.FileSystem != nil {
			fs := ctx.Environment.FileSystem
			if len(fs.ComposeFiles) > 0 {
				prompt.WriteString("Docker Compose Files:\n")
				for _, file := range fs.ComposeFiles {
					prompt.WriteString(fmt.Sprintf("- %s (modified: %s)\n", file.Path, file.ModTime.Format("2006-01-02 15:04:05")))
					if file.Excerpt != "" {
						prompt.WriteString(fmt.Sprintf("  Content excerpt: %s\n", file.Excerpt))
					}
				}
				prompt.WriteString("\n")
			}

			if len(fs.TerraformFiles) > 0 {
				prompt.WriteString("Terraform Files:\n")
				for _, file := range fs.TerraformFiles {
					prompt.WriteString(fmt.Sprintf("- %s (modified: %s)\n", file.Path, file.ModTime.Format("2006-01-02 15:04:05")))
				}
				prompt.WriteString("\n")
			}

			if len(fs.ConfigFiles) > 0 {
				prompt.WriteString("Configuration Files:\n")
				for _, file := range fs.ConfigFiles {
					prompt.WriteString(fmt.Sprintf("- %s (modified: %s)\n", file.Path, file.ModTime.Format("2006-01-02 15:04:05")))
				}
				prompt.WriteString("\n")
			}
		}

		// Add services context
		if ctx.Environment.Services != nil {
			services := ctx.Environment.Services
			if len(services.DockerContainers) > 0 {
				prompt.WriteString("Docker Containers:\n")
				for _, container := range services.DockerContainers {
					prompt.WriteString(fmt.Sprintf("- %s: %s (image: %s, status: %s)\n",
						container.Name, container.ID, container.Image, container.Status))
				}
				prompt.WriteString("\n")
			}
		}

		// Add recent logs
		if ctx.Environment.Logs != nil {
			logs := ctx.Environment.Logs
			if len(logs.RecentErrors) > 0 {
				prompt.WriteString("Recent Errors:\n")
				for _, log := range logs.RecentErrors {
					prompt.WriteString(fmt.Sprintf("- [%s] %s: %s\n",
						log.Timestamp.Format("15:04:05"), log.Service, log.Message))
				}
				prompt.WriteString("\n")
			}
		}

		// Add infrastructure status
		if ctx.Environment.Infrastructure != nil {
			infra := ctx.Environment.Infrastructure
			if infra.VaultStatus != nil {
				prompt.WriteString(fmt.Sprintf("Vault Status: Sealed=%t, Initialized=%t, Version=%s\n",
					infra.VaultStatus.Sealed, infra.VaultStatus.Initialized, infra.VaultStatus.Version))
			}
			if infra.ConsulStatus != nil {
				prompt.WriteString(fmt.Sprintf("Consul Status: Leader=%s, Datacenter=%s\n",
					infra.ConsulStatus.Leader, infra.ConsulStatus.Datacenter))
			}
		}
	}

	prompt.WriteString("=== USER QUERY ===\n\n")
	prompt.WriteString(userQuery)

	return prompt.String()
}

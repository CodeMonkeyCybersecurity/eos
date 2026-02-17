// cmd/ai/ai.go

package ai

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/ai"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/verify"
	"github.com/pmezard/go-difflib/difflib"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

const (
	defaultValidationProfile = "eos-cli-default"
	maxPreviewBytes          = 128 * 1024
)

// AICmd is the root command for AI operations
var AICmd = &cobra.Command{
	Use:   "ai",
	Short: "AI-powered infrastructure management and assistance",
	Long: `AI assistant for infrastructure management, analysis, and troubleshooting.
	
The AI assistant can:
- Analyze your current infrastructure and environment
- Help troubleshoot issues with docker-compose, Terraform, Vault, Consul
- Suggest improvements and optimizations
- Implement fixes and changes with your approval
- Provide interactive conversational support

Examples:
  eos ai ask "Why isn't my docker compose working?"
  eos ai analyze --directory /opt
  eos ai fix "My containers keep crashing"
  eos ai chat
  eos ai implement --dry-run`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return cmd.Help()
	}),
}

var aiAskCmd = &cobra.Command{
	Use:   "ask [question]",
	Short: "Ask the AI assistant a question about your infrastructure",
	Long: `Ask the AI assistant a natural language question about your infrastructure.
	
The AI will analyze your current environment and provide specific, actionable advice.

Examples:
  eos ai ask "Why is my docker compose file not working?"
  eos ai ask "How can I improve my Terraform configuration?"
  eos ai ask "What's wrong with my vault setup?"
  eos ai ask "My containers keep restarting, what should I check?"`,

	Args: cobra.MinimumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// CRITICAL: Detect flag-like args (P0-1 fix)
		if err := verify.ValidateNoFlagLikeArgs(args); err != nil {
			return err
		}
		question := strings.Join(args, " ")

		// Get flags
		workingDir, _ := cmd.Flags().GetString("directory")
		analyze, _ := cmd.Flags().GetBool("analyze")
		verbose, _ := cmd.Flags().GetBool("verbose")

		if workingDir == "" {
			workingDir, _ = os.Getwd()
		}

		logger.Info("Processing AI question",
			zap.String("question", question),
			zap.String("directory", workingDir),
			zap.Bool("analyze", analyze))

		// Initialize AI assistant
		assistant, err := ai.NewAIAssistant(rc)
		if err != nil {
			return fmt.Errorf("failed to initialize AI assistant: %w", err)
		}

		cfg := assistant.Config()
		// Create conversation context
		ctx := ai.NewConversationContext(ai.GetInfrastructureSystemPrompt())
		envOpts := []ai.EnvironmentOption{}
		if cfg != nil {
			envOpts = append(envOpts, ai.WithSecretInclusion(cfg.IncludeSecretFilesEnabled()))
			envOpts = append(envOpts, ai.WithSecretRedaction(cfg.RedactionEnabled()))
		}

		// Analyze environment if requested or if it's a technical question
		if analyze || ai.ContainsTechnicalTerms(question) {
			logger.Info("terminal prompt:  Analyzing current environment...")

			analyzer := ai.NewEnvironmentAnalyzer(workingDir, envOpts...)
			env, err := analyzer.AnalyzeEnvironment(rc)
			if err != nil {
				logger.Warn("Environment analysis failed", zap.Error(err))
			} else {
				ctx.Environment = env
				if verbose {
					logger.Info("terminal prompt: Environment analysis completed",
						zap.Int("files", len(env.FileSystem.ComposeFiles)+len(env.FileSystem.TerraformFiles)+len(env.FileSystem.ConfigFiles)),
						zap.Int("containers", len(env.Services.DockerContainers)),
						zap.Int("services", len(env.Services.SystemdServices)))
				}
			}
		}

		if ctx.Environment != nil && (cfg == nil || cfg.ConsentPromptEnabled()) {
			if err := requireDataSharingConsent(cfg, assistant.Provider()); err != nil {
				return err
			}
		}

		// Build comprehensive prompt with environment context
		fullPrompt := ai.BuildEnvironmentPrompt(ctx, assistant.Provider(), question)

		logger.Info("terminal prompt:  Thinking...")

		// Get AI response
		response, err := assistant.Chat(rc, ctx, fullPrompt)
		if err != nil {
			return fmt.Errorf("AI request failed: %w", err)
		}

		if len(response.Choices) == 0 {
			return fmt.Errorf("no response from AI")
		}

		// Display response
		logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%v", "\n"+strings.Repeat("=", 80))))
		logger.Info("terminal prompt:  AI Assistant Response")
		logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%v", strings.Repeat("=", 80))))
		logger.Info("")
		logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%v", response.Choices[0].Message.Content)))
		logger.Info("")

		// Check for suggested actions
		actions, err := ai.ParseActionsFromResponse(response.Choices[0].Message.Content)
		if err == nil && len(actions) > 0 {
			logger.Info(fmt.Sprintf("terminal prompt:  I found %d suggested action(s). Run 'eos ai implement' to execute them.", len(actions)))

			// Store actions for later implementation (simplified - would use proper storage)
			if verbose {
				logger.Info("terminal prompt: \nSuggested actions:")
				for i, action := range actions {
					logger.Info(fmt.Sprintf("terminal prompt:   %d. %s (%s)", i+1, action.Description, action.Type))
				}
			}
		}

		// Ask if user wants to continue conversation
		logger.Info("terminal prompt: \n Do you have any follow-up questions? [y/N]: ")
		reader := bufio.NewReader(os.Stdin)
		if response, _ := reader.ReadString('\n'); strings.ToLower(strings.TrimSpace(response)) == "y" {
			return ai.StartInteractiveChat(rc, assistant, ctx)
		}

		return nil
	}),
}

var aiAnalyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze current infrastructure and environment",
	Long: `Perform a comprehensive analysis of your current infrastructure environment.
	
This command will:
- Scan for configuration files (docker-compose, Terraform, etc.)
- Check running services and containers
- Analyze recent logs for errors
- Check infrastructure status (Vault, Consul, etc.)
- Provide a detailed report with recommendations

Examples:
  eos ai analyze
  eos ai analyze --directory /opt
  eos ai analyze --detailed`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Get flags
		workingDir, _ := cmd.Flags().GetString("directory")
		detailed, _ := cmd.Flags().GetBool("detailed")
		askAI, _ := cmd.Flags().GetBool("ai-analysis")

		if workingDir == "" {
			workingDir, _ = os.Getwd()
		}

		logger.Info("Starting infrastructure analysis", zap.String("directory", workingDir))

		logger.Info("terminal prompt:  Analyzing infrastructure environment...")
		logger.Info(fmt.Sprintf("terminal prompt:  Working directory: %s", workingDir))

		// Analyze environment
		analyzer := ai.NewEnvironmentAnalyzer(workingDir)
		env, err := analyzer.AnalyzeEnvironment(rc)
		if err != nil {
			return fmt.Errorf("environment analysis failed: %w", err)
		}

		// Display analysis results
		ai.DisplayEnvironmentAnalysis(env, detailed)

		// Get AI analysis if requested
		if askAI {
			logger.Info("terminal prompt: \n Getting AI analysis...")

			assistant, err := ai.NewAIAssistant(rc)
			if err != nil {
				logger.Warn("AI assistant initialization failed", zap.Error(err))
				return nil
			}
			ctx := ai.NewConversationContext(ai.GetInfrastructureSystemPrompt())
			ctx.Environment = env

			analysisPrompt := "Please analyze this infrastructure environment and provide recommendations for improvements, potential issues, and best practices. Focus on security, reliability, and maintainability."

			response, err := assistant.Chat(rc, ctx, analysisPrompt)
			if err != nil {
				logger.Warn("AI analysis failed", zap.Error(err))
			} else if len(response.Choices) > 0 {
				logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%v", "\n"+strings.Repeat("=", 80))))
				logger.Info("terminal prompt:  AI Analysis & Recommendations")
				logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%v", strings.Repeat("=", 80))))
				logger.Info("")
				logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%v", response.Choices[0].Message.Content)))
			}
		}

		return nil
	}),
}

var aiFixCmd = &cobra.Command{
	Use:   "fix [issue]",
	Short: "Ask AI to help fix a specific issue",
	Long: `Ask the AI to help diagnose and fix a specific infrastructure issue.
	
The AI will analyze your environment in the context of the reported issue
and provide specific troubleshooting steps and fixes.

Examples:
  eos ai fix "My docker containers keep crashing"
  eos ai fix "Terraform apply is failing"
  eos ai fix "Vault is sealed and won't unseal"
  eos ai fix "Services can't connect to each other"`,

	Args: cobra.MinimumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		issue := strings.Join(args, " ")

		// Get flags
		workingDir, _ := cmd.Flags().GetString("directory")
		autoFix, _ := cmd.Flags().GetBool("auto-fix")

		if workingDir == "" {
			workingDir, _ = os.Getwd()
		}

		logger.Info(fmt.Sprintf("terminal prompt:  Analyzing issue: %s", issue))

		// Initialize AI assistant
		assistant, err := ai.NewAIAssistant(rc)
		if err != nil {
			return fmt.Errorf("failed to initialize AI assistant: %w", err)
		}
		cfg := assistant.Config()
		ctx := ai.NewConversationContext(ai.GetInfrastructureSystemPrompt())
		envOpts := []ai.EnvironmentOption{}
		if cfg != nil {
			envOpts = append(envOpts, ai.WithSecretInclusion(cfg.IncludeSecretFilesEnabled()))
			envOpts = append(envOpts, ai.WithSecretRedaction(cfg.RedactionEnabled()))
		}

		// Always analyze environment for fix requests
		logger.Info("terminal prompt:  Gathering environment context...")
		analyzer := ai.NewEnvironmentAnalyzer(workingDir, envOpts...)
		env, err := analyzer.AnalyzeEnvironment(rc)
		if err != nil {
			return fmt.Errorf("environment analysis failed: %w", err)
		}
		ctx.Environment = env
		if cfg == nil || cfg.ConsentPromptEnabled() {
			if err := requireDataSharingConsent(cfg, assistant.Provider()); err != nil {
				return err
			}
		}

		// Build diagnostic prompt
		diagnosticPrompt := fmt.Sprintf(`I'm experiencing this issue with my infrastructure: %s

Please help me:
1. Diagnose the root cause of this issue
2. Provide step-by-step troubleshooting instructions
3. Suggest specific fixes or configuration changes
4. Recommend preventive measures to avoid this issue in the future

Focus on actionable solutions that I can implement immediately.`, issue)

		fullPrompt := ai.BuildEnvironmentPrompt(ctx, assistant.Provider(), diagnosticPrompt)

		logger.Info("terminal prompt:  Diagnosing issue...")

		// Get AI response
		response, err := assistant.Chat(rc, ctx, fullPrompt)
		if err != nil {
			return fmt.Errorf("AI diagnosis failed: %w", err)
		}

		if len(response.Choices) == 0 {
			return fmt.Errorf("no response from AI")
		}

		// Display response
		logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%v", "\n"+strings.Repeat("=", 80))))
		logger.Info("terminal prompt:  Diagnostic Results & Fix Recommendations")
		logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%v", strings.Repeat("=", 80))))
		logger.Info("")
		logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%v", response.Choices[0].Message.Content)))
		logger.Info("")

		// Parse and offer to implement actions
		actions, err := ai.ParseActionsFromResponse(response.Choices[0].Message.Content)
		if err == nil && len(actions) > 0 {
			logger.Info(fmt.Sprintf("terminal prompt:  Found %d suggested fix action(s).", len(actions)))
			policy := ai.BuildActionPolicy(cfg, workingDir)
			reader := bufio.NewReader(os.Stdin)
			policyPath, _ := cmd.Flags().GetString("auto-fix-policy")
			var policyDoc *autoFixPolicyDocument
			if policyPath != "" {
				secrets := [][]byte{}
				if cfg != nil {
					secrets = cfg.PolicySecretBytes()
				}
				policyDoc, err = loadAutoFixPolicy(policyPath, secrets)
				if err != nil {
					return err
				}
			}
			if autoFix && (policyDoc == nil || !policyDoc.AllowsAutoFix()) {
				logger.Info("terminal prompt:  Auto-fix requested but no valid signed policy found; prompting for manual approval")
			}
			approvalProfile := defaultValidationProfile
			if policyDoc != nil && policyDoc.ValidationTag != "" {
				approvalProfile = policyDoc.ValidationTag
			}
			autoApproved := autoFix && policyDoc != nil && policyDoc.AllowsAutoFix()
			approvedActions, err := reviewActionsWithOperator(logger, reader, actions, workingDir, autoApproved)
			if err != nil {
				return err
			}
			if len(approvedActions) == 0 {
				logger.Info("terminal prompt:  No actions were approved; exiting without changes.")
				return nil
			}
			ai.InjectValidationProfile(approvedActions, approvalProfile, policy)
			return ai.ImplementActions(rc, approvedActions, workingDir, false, policy)
		}

		return nil
	}),
}

var aiChatCmd = &cobra.Command{
	Use:   "chat",
	Short: "Start an interactive conversation with the AI assistant",
	Long: `Start an interactive conversational session with the AI assistant.
	
In chat mode, you can have a back-and-forth conversation about your
infrastructure, ask follow-up questions, and iteratively work on improvements.

Type 'exit', 'quit', or 'bye' to end the conversation.

Example:
  eos ai chat`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		// Get flags
		workingDir, _ := cmd.Flags().GetString("directory")

		if workingDir == "" {
			workingDir, _ = os.Getwd()
		}

		logger.Info("terminal prompt:  AI Assistant Chat Mode")
		logger.Info("terminal prompt: Type 'exit', 'quit', or 'bye' to end the conversation.")
		logger.Info("terminal prompt: Working directory", zap.String("dir", workingDir))
		logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%v", strings.Repeat("-", 60))))

		// Initialize AI assistant
		assistant, err := ai.NewAIAssistant(rc)
		if err != nil {
			return fmt.Errorf("failed to initialize AI assistant: %w", err)
		}
		ctx := ai.NewConversationContext(ai.GetInfrastructureSystemPrompt())

		// Initial environment analysis
		logger.Info("terminal prompt:  Analyzing environment...")
		analyzer := ai.NewEnvironmentAnalyzer(workingDir)
		env, err := analyzer.AnalyzeEnvironment(rc)
		if err != nil {
			logger.Info(fmt.Sprintf("terminal prompt:  Environment analysis failed: %v", err))
		} else {
			ctx.Environment = env
			logger.Info("terminal prompt:  Environment analysis complete.")
		}
		logger.Info("")

		return ai.StartInteractiveChat(rc, assistant, ctx)
	}),
}

var aiImplementCmd = &cobra.Command{
	Use:   "implement",
	Short: "Implement AI-suggested actions",
	Long: `Implement actions suggested by the AI assistant.
	
This command can execute file modifications, run commands, and make
infrastructure changes based on AI recommendations.

Examples:
  eos ai implement --dry-run
  eos ai implement --confirm-all
  eos ai implement --action-file suggestions.json`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		// Get flags
		workingDir, _ := cmd.Flags().GetString("directory")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		_, _ = cmd.Flags().GetBool("confirm-all") // Reserved for future use
		actionFile, _ := cmd.Flags().GetString("action-file")

		if workingDir == "" {
			workingDir, _ = os.Getwd()
		}

		// For now, implement a placeholder that shows how it would work
		logger.Info("terminal prompt:  AI Action Implementation")
		logger.Info("terminal prompt: Working directory", zap.String("dir", workingDir))
		if dryRun {
			logger.Info("terminal prompt:  DRY RUN MODE - No actual changes will be made")
		}
		logger.Info("")

		// In a full implementation, this would:
		// 1. Load actions from storage or file
		// 2. Present actions to user for confirmation
		// 3. Execute approved actions using ActionExecutor
		// 4. Provide feedback on results

		// var actions []*ai.Action // Reserved for future implementation

		if actionFile != "" {
			logger.Info("terminal prompt:  Loading actions from", zap.String("file", actionFile))
			// Would load actions from JSON file
			logger.Info("terminal prompt:  Action file loading not yet implemented")
			return nil
		} else {
			logger.Info("terminal prompt:  No previous AI suggestions found.")
			logger.Info("terminal prompt: Run 'eos ai ask' or 'eos ai fix' first to get suggestions.")
			return nil
		}

		// This line is unreachable due to return above, but kept for future implementation
		// return implementActions(rc, actions, workingDir, dryRun)
	}),
}

var aiConfigureCmd = &cobra.Command{
	Use:   "configure",
	Short: "Configure AI assistant settings",
	Long: `Configure the AI assistant settings including API key, model, and other options.
	
This command allows you to:
- Choose AI provider (Anthropic Claude or Azure OpenAI)
- Set your API key (stored securely in config file)
- Configure Vault integration for API key storage
- Select AI model
- Configure Azure OpenAI specific settings
- Adjust other settings

Examples:
  eos ai configure
  eos ai configure --provider anthropic --api-key "sk-..."
  eos ai configure --provider azure-openai --azure-endpoint "https://myresource.openai.azure.com"
  eos ai configure --vault-path "secret/ai/api-key"
  eos ai configure --model "gpt-4"`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Get flags
		provider, _ := cmd.Flags().GetString("provider")
		apiKey, _ := cmd.Flags().GetString("api-key")
		vaultPath, _ := cmd.Flags().GetString("vault-path")
		model, _ := cmd.Flags().GetString("model")
		baseURL, _ := cmd.Flags().GetString("base-url")
		azureEndpoint, _ := cmd.Flags().GetString("azure-endpoint")
		azureAPIVersion, _ := cmd.Flags().GetString("azure-api-version")
		azureDeployment, _ := cmd.Flags().GetString("azure-deployment")
		showConfig, _ := cmd.Flags().GetBool("show")

		// Load configuration manager
		configManager := ai.NewConfigManager()
		if err := configManager.LoadConfig(); err != nil {
			logger.Warn("Failed to load existing config", zap.Error(err))
		}

		// Show current configuration if requested
		if showConfig {
			config := configManager.GetConfig()
			logger.Info("terminal prompt:  Current AI Configuration")
			logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%v", strings.Repeat("-", 40))))
			logger.Info("terminal prompt: Config file", zap.String("path", configManager.GetConfigPath()))

			provider := config.Provider
			if provider == "" {
				provider = "anthropic"
			}
			logger.Info("terminal prompt: Provider", zap.String("provider", provider))

			logger.Info("terminal prompt: API Key", zap.String("key", ai.MaskAPIKey(config.APIKey)))
			if config.APIKeyVault != "" {
				logger.Info(fmt.Sprintf("terminal prompt: API Key Vault Path: %s", config.APIKeyVault))
			}

			if provider == "azure-openai" {
				if config.AzureEndpoint != "" {
					logger.Info(fmt.Sprintf("terminal prompt: Azure Endpoint: %s", config.AzureEndpoint))
				}
				if config.AzureAPIVersion != "" {
					logger.Info(fmt.Sprintf("terminal prompt: Azure API Version: %s", config.AzureAPIVersion))
				}
				if config.AzureDeployment != "" {
					logger.Info(fmt.Sprintf("terminal prompt: Azure Deployment: %s", config.AzureDeployment))
				}
			} else {
				if config.BaseURL != "" {
					logger.Info(fmt.Sprintf("terminal prompt: Base URL: %s", config.BaseURL))
				}
			}

			logger.Info(fmt.Sprintf("terminal prompt: Model: %s", config.Model))
			logger.Info(fmt.Sprintf("terminal prompt: Max Tokens: %d", config.MaxTokens))
			logger.Info(fmt.Sprintf("terminal prompt: Timeout: %d seconds", config.Timeout))
			return nil
		}

		// Interactive mode if no flags provided
		if provider == "" && apiKey == "" && vaultPath == "" && model == "" && baseURL == "" && azureEndpoint == "" {
			logger.Info("terminal prompt:  AI Assistant Configuration")
			logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%v", strings.Repeat("-", 40))))
			logger.Info(fmt.Sprintf("terminal prompt: Config file: %s", configManager.GetConfigPath()))

			reader := bufio.NewReader(os.Stdin)

			// Provider selection
			logger.Info("terminal prompt: 1. Provider Selection")
			logger.Info("terminal prompt:    Choose your AI provider:")
			logger.Info("terminal prompt:    a) Anthropic Claude (default)")
			logger.Info("terminal prompt:    b) Azure OpenAI")
			logger.Info("terminal prompt: \nYour choice [a/b]: ")

			providerChoice, _ := reader.ReadString('\n')
			providerChoice = strings.TrimSpace(strings.ToLower(providerChoice))

			selectedProvider := "anthropic"
			if providerChoice == "b" {
				selectedProvider = "azure-openai"
			}

			// Apply provider defaults
			updates := map[string]any{"provider": selectedProvider}
			if err := configManager.UpdateConfig(updates); err != nil {
				return fmt.Errorf("failed to set provider: %w", err)
			}

			// API Key configuration
			logger.Info(fmt.Sprintf("terminal prompt: \n2. API Key Configuration (%s)", selectedProvider))
			logger.Info("terminal prompt:    Choose how to provide your API key:")
			logger.Info("terminal prompt:    a) Enter API key directly (stored in config file)")
			logger.Info("terminal prompt:    b) Use Vault path (recommended for production)")
			logger.Info("terminal prompt:    c) Skip (use environment variable)")
			logger.Info("terminal prompt: \nYour choice [a/b/c]: ")

			choice, _ := reader.ReadString('\n')
			choice = strings.TrimSpace(strings.ToLower(choice))

			switch choice {
			case "a":
				if selectedProvider == "azure-openai" {
					logger.Info("terminal prompt: \nEnter your Azure OpenAI API key: ")
				} else {
					logger.Info("terminal prompt: \nEnter your Anthropic API key: ")
				}
				apiKeyInput, _ := reader.ReadString('\n')
				apiKeyInput = strings.TrimSpace(apiKeyInput)

				if apiKeyInput != "" {
					if err := ai.ValidateAPIKey(apiKeyInput); err != nil {
						logger.Info(fmt.Sprintf("terminal prompt:  Warning: %v", err))
					}
					if err := configManager.SetAPIKey(apiKeyInput); err != nil {
						return fmt.Errorf("failed to save API key: %w", err)
					}
					logger.Info("terminal prompt:  API key saved to config file")
				}

			case "b":
				logger.Info("terminal prompt: \nEnter Vault path for API key (e.g., secret/ai/api-key): ")
				vaultInput, _ := reader.ReadString('\n')
				vaultInput = strings.TrimSpace(vaultInput)

				if vaultInput != "" {
					if err := configManager.SetAPIKeyVault(vaultInput); err != nil {
						return fmt.Errorf("failed to save Vault path: %w", err)
					}
					logger.Info("terminal prompt:  Vault path saved to config file")
					logger.Info("terminal prompt:  Note: Make sure to store your API key at this Vault path")
				}

			case "c":
				logger.Info("terminal prompt:  Skipping API key configuration")
				logger.Info("terminal prompt:    Set one of these environment variables:")
				if selectedProvider == "azure-openai" {
					logger.Info("terminal prompt:    - AZURE_OPENAI_API_KEY")
					logger.Info("terminal prompt:    - OPENAI_API_KEY")
				} else {
					logger.Info("terminal prompt:    - ANTHROPIC_API_KEY")
					logger.Info("terminal prompt:    - CLAUDE_API_KEY")
				}
				logger.Info("terminal prompt:    - AI_API_KEY")
			}

			// Azure OpenAI specific configuration
			if selectedProvider == "azure-openai" {
				logger.Info("terminal prompt: \n3. Azure OpenAI Configuration")

				logger.Info("terminal prompt: Enter your Azure OpenAI endpoint (e.g., https://myresource.openai.azure.com): ")
				endpointInput, _ := reader.ReadString('\n')
				endpointInput = strings.TrimSpace(endpointInput)

				if endpointInput != "" {
					updates := map[string]any{"azure_endpoint": endpointInput}
					if err := configManager.UpdateConfig(updates); err != nil {
						return fmt.Errorf("failed to save Azure endpoint: %w", err)
					}
					logger.Info("terminal prompt:  Azure endpoint saved")
				}

				logger.Info("terminal prompt: Enter your deployment name (e.g., gpt-4): ")
				deploymentInput, _ := reader.ReadString('\n')
				deploymentInput = strings.TrimSpace(deploymentInput)

				if deploymentInput != "" {
					updates := map[string]any{"azure_deployment": deploymentInput}
					if err := configManager.UpdateConfig(updates); err != nil {
						return fmt.Errorf("failed to save Azure deployment: %w", err)
					}
					logger.Info("terminal prompt:  Azure deployment saved")
				}

				logger.Info("terminal prompt: Enter API version (press Enter for default 2024-02-15-preview): ")
				versionInput, _ := reader.ReadString('\n')
				versionInput = strings.TrimSpace(versionInput)

				if versionInput != "" {
					updates := map[string]any{"azure_api_version": versionInput}
					if err := configManager.UpdateConfig(updates); err != nil {
						return fmt.Errorf("failed to save Azure API version: %w", err)
					}
					logger.Info(fmt.Sprintf("terminal prompt:  Azure API version set to: %s", versionInput))
				}
			}

			// Model selection
			logger.Info("terminal prompt: \nSelect AI model (press Enter for default): ")
			modelInput, _ := reader.ReadString('\n')
			modelInput = strings.TrimSpace(modelInput)

			if modelInput != "" {
				updates := map[string]any{"model": modelInput}
				if err := configManager.UpdateConfig(updates); err != nil {
					return fmt.Errorf("failed to update model: %w", err)
				}
				logger.Info(fmt.Sprintf("terminal prompt:  Model set to: %s", modelInput))
			}

			logger.Info("terminal prompt: \n Configuration complete!")
			logger.Info("terminal prompt: You can now use 'eos ai ask' and other AI commands.")
			return nil
		}

		// Non-interactive mode - apply flags
		updates := make(map[string]any)

		if provider != "" {
			updates["provider"] = provider
			logger.Info(fmt.Sprintf("terminal prompt:  Provider set to: %s", provider))
		}

		if apiKey != "" {
			if err := ai.ValidateAPIKey(apiKey); err != nil {
				logger.Info(fmt.Sprintf("terminal prompt:  Warning: %v", err))
			}
			if err := configManager.SetAPIKey(apiKey); err != nil {
				return fmt.Errorf("failed to save API key: %w", err)
			}
			logger.Info("terminal prompt:  API key saved")
		}

		if vaultPath != "" {
			if err := configManager.SetAPIKeyVault(vaultPath); err != nil {
				return fmt.Errorf("failed to save Vault path: %w", err)
			}
			logger.Info("terminal prompt:  Vault path saved")
		}

		if model != "" {
			updates["model"] = model
		}

		if baseURL != "" {
			updates["base_url"] = baseURL
		}

		if azureEndpoint != "" {
			updates["azure_endpoint"] = azureEndpoint
		}

		if azureAPIVersion != "" {
			updates["azure_api_version"] = azureAPIVersion
		}

		if azureDeployment != "" {
			updates["azure_deployment"] = azureDeployment
		}

		if len(updates) > 0 {
			if err := configManager.UpdateConfig(updates); err != nil {
				return fmt.Errorf("failed to update configuration: %w", err)
			}
			logger.Info("terminal prompt:  Configuration updated")
		}

		return nil
	}),
}

func init() {
	// AI ask command flags
	aiAskCmd.Flags().String("directory", "", "Working directory to analyze (default: current)")
	aiAskCmd.Flags().Bool("analyze", true, "Analyze environment before answering")
	aiAskCmd.Flags().Bool("verbose", false, "Show detailed analysis information")

	// AI analyze command flags
	aiAnalyzeCmd.Flags().String("directory", "", "Directory to analyze (default: current)")
	aiAnalyzeCmd.Flags().Bool("detailed", false, "Show detailed analysis results")
	aiAnalyzeCmd.Flags().Bool("ai-analysis", true, "Get AI-powered analysis and recommendations")

	// AI fix command flags
	aiFixCmd.Flags().String("directory", "", "Working directory (default: current)")
	aiFixCmd.Flags().Bool("auto-fix", false, "Automatically implement suggested fixes")
	aiFixCmd.Flags().String("auto-fix-policy", "", "Path to signed policy that authorizes unattended fixes")

	// AI chat command flags
	aiChatCmd.Flags().String("directory", "", "Working directory (default: current)")

	// AI implement command flags
	aiImplementCmd.Flags().String("directory", "", "Working directory (default: current)")
	aiImplementCmd.Flags().Bool("dry-run", false, "Show what would be done without making changes")
	aiImplementCmd.Flags().Bool("confirm-all", false, "Skip individual confirmations")
	aiImplementCmd.Flags().String("action-file", "", "Load actions from JSON file")

	// AI configure command flags
	aiConfigureCmd.Flags().String("provider", "", "AI provider: anthropic or azure-openai")
	aiConfigureCmd.Flags().String("api-key", "", "API key for the selected provider")
	aiConfigureCmd.Flags().String("vault-path", "", "Vault path for API key storage")
	aiConfigureCmd.Flags().String("model", "", "AI model to use")
	aiConfigureCmd.Flags().String("base-url", "", "API base URL (Anthropic only)")
	aiConfigureCmd.Flags().String("azure-endpoint", "", "Azure OpenAI endpoint")
	aiConfigureCmd.Flags().String("azure-api-version", "", "Azure OpenAI API version")
	aiConfigureCmd.Flags().String("azure-deployment", "", "Azure OpenAI deployment name")
	aiConfigureCmd.Flags().Bool("show", false, "Show current configuration")

	// Add subcommands
	AICmd.AddCommand(aiAskCmd)
	AICmd.AddCommand(aiAnalyzeCmd)
	AICmd.AddCommand(aiFixCmd)
	AICmd.AddCommand(aiChatCmd)
	AICmd.AddCommand(aiImplementCmd)
	AICmd.AddCommand(aiConfigureCmd)
}

var (
	previewKeyValueRegex    = regexp.MustCompile(`(?i)(token|password|secret|apikey|api_key|bearer|session|authorization)[\s:=\"']+([A-Za-z0-9\-_.:/+=]+)`) //nolint:lll
	previewHighEntropyRegex = regexp.MustCompile(`[A-Za-z0-9+/=_-]{40,}`)
)

func requireDataSharingConsent(cfg *ai.AIConfig, provider string) error {
	if cfg != nil && !cfg.ConsentPromptEnabled() {
		return nil
	}
	reader := bufio.NewReader(os.Stdin)
	return promptDataSharingConsent(reader, provider)
}

func promptDataSharingConsent(reader *bufio.Reader, provider string) error {
	if provider == "" {
		provider = "the configured AI provider"
	}
	fmt.Printf("WARNING: Sanitized environment context will be shared with %s. Proceed? [y/N]: ", provider)
	response, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	answer := strings.ToLower(strings.TrimSpace(response))
	if answer == "y" || answer == "yes" {
		return nil
	}
	return errors.New("operator declined to share environment context")
}

func reviewActionsWithOperator(logger otelzap.LoggerWithCtx, reader *bufio.Reader, actions []*ai.Action, workingDir string, autoApprove bool) ([]*ai.Action, error) {
	var approved []*ai.Action
	for i, action := range actions {
		if action == nil {
			continue
		}
		descriptor := fmt.Sprintf("Action %d/%d: %s (%s)", i+1, len(actions), action.Description, action.Type)
		logger.Info("terminal prompt:", zap.String("output", descriptor))
		preview := renderActionPreview(action, workingDir)
		if strings.TrimSpace(preview) != "" {
			logger.Info("terminal prompt:", zap.String("output", preview))
		}
		approve := autoApprove
		if !approve {
			var err error
			approve, err = promptActionApproval(reader)
			if err != nil {
				return nil, err
			}
		}
		if approve {
			approved = append(approved, action)
			logger.Info("terminal prompt:  Approved action.")
		} else {
			logger.Info("terminal prompt:  Skipped action per operator request.")
		}
	}
	return approved, nil
}

func promptActionApproval(reader *bufio.Reader) (bool, error) {
	fmt.Print("Apply this action? [y/N]: ")
	response, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}
	answer := strings.ToLower(strings.TrimSpace(response))
	return answer == "y" || answer == "yes", nil
}

func renderActionPreview(action *ai.Action, workingDir string) string {
	switch action.Type {
	case ai.ActionTypeFileCreate, ai.ActionTypeFileModify:
		return buildFileDiff(action, workingDir)
	case ai.ActionTypeFileDelete:
		return fmt.Sprintf("File %s will be deleted", filepath.Join(workingDir, action.Target))
	case ai.ActionTypeCommand:
		return fmt.Sprintf("Command: %s", formatCommandLine(action))
	case ai.ActionTypeService, ai.ActionTypeContainer, ai.ActionTypeTerraform, ai.ActionTypeVault, ai.ActionTypeConsul:
		return fmt.Sprintf("Action details: target=%s, command=%s", action.Target, formatCommandLine(action))
	default:
		return ""
	}
}

func buildFileDiff(action *ai.Action, workingDir string) string {
	resolved := filepath.Join(workingDir, filepath.Clean(action.Target))
	var original string
	if data, err := os.ReadFile(resolved); err == nil {
		if len(data) > maxPreviewBytes {
			data = data[:maxPreviewBytes]
		}
		original = sanitizePreviewText(string(data))
	}
	proposedContent := action.Content
	if len(proposedContent) > maxPreviewBytes {
		proposedContent = proposedContent[:maxPreviewBytes]
	}
	proposed := sanitizePreviewText(proposedContent)
	diff := difflib.UnifiedDiff{
		A:        difflib.SplitLines(original),
		B:        difflib.SplitLines(proposed),
		FromFile: resolved,
		ToFile:   resolved + " (proposed)",
		Context:  3,
	}
	result, err := difflib.GetUnifiedDiffString(diff)
	if err != nil {
		return fmt.Sprintf("unable to render diff: %v", err)
	}
	if strings.TrimSpace(result) == "" {
		if original == "" {
			return fmt.Sprintf("New file will be created at %s", resolved)
		}
		return "No textual diff detected"
	}
	return result
}

func formatCommandLine(action *ai.Action) string {
	parts := append([]string{action.Command}, action.Arguments...)
	return sanitizePreviewText(strings.Join(parts, " "))
}

func sanitizePreviewText(text string) string {
	trimmed := strings.TrimSpace(text)
	trimmed = previewKeyValueRegex.ReplaceAllString(trimmed, "$1 <redacted>")
	trimmed = previewHighEntropyRegex.ReplaceAllString(trimmed, "<redacted>")
	if len(trimmed) > 400 {
		trimmed = trimmed[:400] + "..."
	}
	return trimmed
}

type autoFixPolicyDocument struct {
	Name          string `json:"name"`
	AllowAutoFix  bool   `json:"allow_auto_fix"`
	Scope         string `json:"scope"`
	ExpiresAt     string `json:"expires_at"`
	Signature     string `json:"signature"`
	ValidationTag string `json:"validation_profile"`
	parsedExpiry  time.Time
}

func (doc *autoFixPolicyDocument) AllowsAutoFix() bool {
	if doc == nil || !doc.AllowAutoFix {
		return false
	}
	if doc.parsedExpiry.IsZero() {
		return true
	}
	return time.Now().Before(doc.parsedExpiry)
}

func loadAutoFixPolicy(path string, secrets [][]byte) (*autoFixPolicyDocument, error) {
	if path == "" {
		return nil, fmt.Errorf("auto-fix policy path not provided")
	}
	if len(secrets) == 0 {
		return nil, fmt.Errorf("no trusted policy secrets configured; cannot verify %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}
	var doc autoFixPolicyDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("invalid policy file: %w", err)
	}
	if doc.Signature == "" {
		return nil, fmt.Errorf("policy %s missing signature", path)
	}
	payload := doc
	payload.Signature = ""
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	signatureBytes, err := hex.DecodeString(strings.TrimSpace(doc.Signature))
	if err != nil {
		return nil, fmt.Errorf("policy signature decoding failed: %w", err)
	}
	for _, secret := range secrets {
		mac := hmac.New(sha256.New, secret)
		mac.Write(payloadBytes)
		if hmac.Equal(mac.Sum(nil), signatureBytes) {
			if doc.ExpiresAt != "" {
				parsed, err := time.Parse(time.RFC3339, doc.ExpiresAt)
				if err != nil {
					return nil, fmt.Errorf("invalid policy expiry: %w", err)
				}
				doc.parsedExpiry = parsed
			}
			return &doc, nil
		}
	}
	return nil, fmt.Errorf("policy %s failed signature verification", path)
}

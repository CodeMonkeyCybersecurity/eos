// cmd/ai/ai.go

package ai

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/ai"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
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
  eos ai ask "Why isn't my docker-compose working?"
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
  eos ai ask "Why is my docker-compose file not working?"
  eos ai ask "How can I improve my Terraform configuration?"
  eos ai ask "What's wrong with my vault setup?"
  eos ai ask "My containers keep restarting, what should I check?"`,

	Args: cobra.MinimumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
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

		// Create conversation context
		ctx := ai.NewConversationContext(ai.GetInfrastructureSystemPrompt())

		// Analyze environment if requested or if it's a technical question
		if analyze || containsTechnicalTerms(question) {
			fmt.Println(" Analyzing current environment...")

			analyzer := ai.NewEnvironmentAnalyzer(workingDir)
			env, err := analyzer.AnalyzeEnvironment(rc)
			if err != nil {
				logger.Warn("Environment analysis failed", zap.Error(err))
			} else {
				ctx.Environment = env
				if verbose {
					fmt.Printf(" Environment analysis completed: %d files, %d containers, %d services\n",
						len(env.FileSystem.ComposeFiles)+len(env.FileSystem.TerraformFiles)+len(env.FileSystem.ConfigFiles),
						len(env.Services.DockerContainers),
						len(env.Services.SystemdServices))
				}
			}
		}

		// Build comprehensive prompt with environment context
		fullPrompt := ai.BuildEnvironmentPrompt(ctx, question)

		fmt.Println(" Thinking...")

		// Get AI response
		response, err := assistant.Chat(rc, ctx, fullPrompt)
		if err != nil {
			return fmt.Errorf("AI request failed: %w", err)
		}

		if len(response.Choices) == 0 {
			return fmt.Errorf("no response from AI")
		}

		// Display response
		fmt.Println("\n" + strings.Repeat("=", 80))
		fmt.Println(" AI Assistant Response")
		fmt.Println(strings.Repeat("=", 80))
		fmt.Println()
		fmt.Println(response.Choices[0].Message.Content)
		fmt.Println()

		// Check for suggested actions
		actions, err := ai.ParseActionsFromResponse(response.Choices[0].Message.Content)
		if err == nil && len(actions) > 0 {
			fmt.Printf(" I found %d suggested action(s). Run 'eos ai implement' to execute them.\n", len(actions))

			// Store actions for later implementation (simplified - would use proper storage)
			if verbose {
				fmt.Println("\nSuggested actions:")
				for i, action := range actions {
					fmt.Printf("  %d. %s (%s)\n", i+1, action.Description, action.Type)
				}
			}
		}

		// Ask if user wants to continue conversation
		fmt.Print("\n Do you have any follow-up questions? [y/N]: ")
		reader := bufio.NewReader(os.Stdin)
		if response, _ := reader.ReadString('\n'); strings.ToLower(strings.TrimSpace(response)) == "y" {
			return startInteractiveChat(rc, assistant, ctx)
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

		fmt.Println(" Analyzing infrastructure environment...")
		fmt.Printf(" Working directory: %s\n\n", workingDir)

		// Analyze environment
		analyzer := ai.NewEnvironmentAnalyzer(workingDir)
		env, err := analyzer.AnalyzeEnvironment(rc)
		if err != nil {
			return fmt.Errorf("environment analysis failed: %w", err)
		}

		// Display analysis results
		displayEnvironmentAnalysis(env, detailed)

		// Get AI analysis if requested
		if askAI {
			fmt.Println("\n Getting AI analysis...")

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
				fmt.Println("\n" + strings.Repeat("=", 80))
				fmt.Println(" AI Analysis & Recommendations")
				fmt.Println(strings.Repeat("=", 80))
				fmt.Println()
				fmt.Println(response.Choices[0].Message.Content)
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
		issue := strings.Join(args, " ")

		// Get flags
		workingDir, _ := cmd.Flags().GetString("directory")
		autoFix, _ := cmd.Flags().GetBool("auto-fix")

		if workingDir == "" {
			workingDir, _ = os.Getwd()
		}

		fmt.Printf(" Analyzing issue: %s\n\n", issue)

		// Initialize AI assistant
		assistant, err := ai.NewAIAssistant(rc)
		if err != nil {
			return fmt.Errorf("failed to initialize AI assistant: %w", err)
		}
		ctx := ai.NewConversationContext(ai.GetInfrastructureSystemPrompt())

		// Always analyze environment for fix requests
		fmt.Println(" Gathering environment context...")
		analyzer := ai.NewEnvironmentAnalyzer(workingDir)
		env, err := analyzer.AnalyzeEnvironment(rc)
		if err != nil {
			return fmt.Errorf("environment analysis failed: %w", err)
		}
		ctx.Environment = env

		// Build diagnostic prompt
		diagnosticPrompt := fmt.Sprintf(`I'm experiencing this issue with my infrastructure: %s

Please help me:
1. Diagnose the root cause of this issue
2. Provide step-by-step troubleshooting instructions
3. Suggest specific fixes or configuration changes
4. Recommend preventive measures to avoid this issue in the future

Focus on actionable solutions that I can implement immediately.`, issue)

		fullPrompt := ai.BuildEnvironmentPrompt(ctx, diagnosticPrompt)

		fmt.Println(" Diagnosing issue...")

		// Get AI response
		response, err := assistant.Chat(rc, ctx, fullPrompt)
		if err != nil {
			return fmt.Errorf("AI diagnosis failed: %w", err)
		}

		if len(response.Choices) == 0 {
			return fmt.Errorf("no response from AI")
		}

		// Display response
		fmt.Println("\n" + strings.Repeat("=", 80))
		fmt.Println(" Diagnostic Results & Fix Recommendations")
		fmt.Println(strings.Repeat("=", 80))
		fmt.Println()
		fmt.Println(response.Choices[0].Message.Content)
		fmt.Println()

		// Parse and offer to implement actions
		actions, err := ai.ParseActionsFromResponse(response.Choices[0].Message.Content)
		if err == nil && len(actions) > 0 {
			fmt.Printf(" Found %d suggested fix action(s).\n", len(actions))

			if autoFix {
				fmt.Println(" Auto-fix enabled, implementing suggestions...")
				return implementActions(rc, actions, workingDir, false)
			} else {
				fmt.Print(" Would you like me to implement these fixes? [y/N]: ")
				reader := bufio.NewReader(os.Stdin)
				if response, _ := reader.ReadString('\n'); strings.ToLower(strings.TrimSpace(response)) == "y" {
					return implementActions(rc, actions, workingDir, false)
				}
			}
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
		// Get flags
		workingDir, _ := cmd.Flags().GetString("directory")

		if workingDir == "" {
			workingDir, _ = os.Getwd()
		}

		fmt.Println(" AI Assistant Chat Mode")
		fmt.Println("Type 'exit', 'quit', or 'bye' to end the conversation.")
		fmt.Printf("Working directory: %s\n", workingDir)
		fmt.Println(strings.Repeat("-", 60))

		// Initialize AI assistant
		assistant, err := ai.NewAIAssistant(rc)
		if err != nil {
			return fmt.Errorf("failed to initialize AI assistant: %w", err)
		}
		ctx := ai.NewConversationContext(ai.GetInfrastructureSystemPrompt())

		// Initial environment analysis
		fmt.Println(" Analyzing environment...")
		analyzer := ai.NewEnvironmentAnalyzer(workingDir)
		env, err := analyzer.AnalyzeEnvironment(rc)
		if err != nil {
			fmt.Printf(" Environment analysis failed: %v\n", err)
		} else {
			ctx.Environment = env
			fmt.Println(" Environment analysis complete.")
		}
		fmt.Println()

		return startInteractiveChat(rc, assistant, ctx)
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
		// Get flags
		workingDir, _ := cmd.Flags().GetString("directory")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		_, _ = cmd.Flags().GetBool("confirm-all") // Reserved for future use
		actionFile, _ := cmd.Flags().GetString("action-file")

		if workingDir == "" {
			workingDir, _ = os.Getwd()
		}

		// For now, implement a placeholder that shows how it would work
		fmt.Println(" AI Action Implementation")
		fmt.Printf("Working directory: %s\n", workingDir)
		if dryRun {
			fmt.Println(" DRY RUN MODE - No actual changes will be made")
		}
		fmt.Println()

		// In a full implementation, this would:
		// 1. Load actions from storage or file
		// 2. Present actions to user for confirmation
		// 3. Execute approved actions using ActionExecutor
		// 4. Provide feedback on results

		// var actions []*ai.Action // Reserved for future implementation

		if actionFile != "" {
			fmt.Printf(" Loading actions from: %s\n", actionFile)
			// Would load actions from JSON file
			fmt.Println(" Action file loading not yet implemented")
			return nil
		} else {
			fmt.Println(" No previous AI suggestions found.")
			fmt.Println("Run 'eos ai ask' or 'eos ai fix' first to get suggestions.")
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
			fmt.Println(" Current AI Configuration")
			fmt.Println(strings.Repeat("-", 40))
			fmt.Printf("Config file: %s\n", configManager.GetConfigPath())

			provider := config.Provider
			if provider == "" {
				provider = "anthropic"
			}
			fmt.Printf("Provider: %s\n", provider)

			fmt.Printf("API Key: %s\n", maskAPIKey(config.APIKey))
			if config.APIKeyVault != "" {
				fmt.Printf("API Key Vault Path: %s\n", config.APIKeyVault)
			}

			if provider == "azure-openai" {
				if config.AzureEndpoint != "" {
					fmt.Printf("Azure Endpoint: %s\n", config.AzureEndpoint)
				}
				if config.AzureAPIVersion != "" {
					fmt.Printf("Azure API Version: %s\n", config.AzureAPIVersion)
				}
				if config.AzureDeployment != "" {
					fmt.Printf("Azure Deployment: %s\n", config.AzureDeployment)
				}
			} else {
				if config.BaseURL != "" {
					fmt.Printf("Base URL: %s\n", config.BaseURL)
				}
			}

			fmt.Printf("Model: %s\n", config.Model)
			fmt.Printf("Max Tokens: %d\n", config.MaxTokens)
			fmt.Printf("Timeout: %d seconds\n", config.Timeout)
			return nil
		}

		// Interactive mode if no flags provided
		if provider == "" && apiKey == "" && vaultPath == "" && model == "" && baseURL == "" && azureEndpoint == "" {
			fmt.Println(" AI Assistant Configuration")
			fmt.Println(strings.Repeat("-", 40))
			fmt.Printf("Config file: %s\n\n", configManager.GetConfigPath())

			reader := bufio.NewReader(os.Stdin)

			// Provider selection
			fmt.Println("1. Provider Selection")
			fmt.Println("   Choose your AI provider:")
			fmt.Println("   a) Anthropic Claude (default)")
			fmt.Println("   b) Azure OpenAI")
			fmt.Print("\nYour choice [a/b]: ")

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
			fmt.Printf("\n2. API Key Configuration (%s)\n", selectedProvider)
			fmt.Println("   Choose how to provide your API key:")
			fmt.Println("   a) Enter API key directly (stored in config file)")
			fmt.Println("   b) Use Vault path (recommended for production)")
			fmt.Println("   c) Skip (use environment variable)")
			fmt.Print("\nYour choice [a/b/c]: ")

			choice, _ := reader.ReadString('\n')
			choice = strings.TrimSpace(strings.ToLower(choice))

			switch choice {
			case "a":
				if selectedProvider == "azure-openai" {
					fmt.Print("\nEnter your Azure OpenAI API key: ")
				} else {
					fmt.Print("\nEnter your Anthropic API key: ")
				}
				apiKeyInput, _ := reader.ReadString('\n')
				apiKeyInput = strings.TrimSpace(apiKeyInput)

				if apiKeyInput != "" {
					if err := ai.ValidateAPIKey(apiKeyInput); err != nil {
						fmt.Printf(" Warning: %v\n", err)
					}
					if err := configManager.SetAPIKey(apiKeyInput); err != nil {
						return fmt.Errorf("failed to save API key: %w", err)
					}
					fmt.Println(" API key saved to config file")
				}

			case "b":
				fmt.Print("\nEnter Vault path for API key (e.g., secret/ai/api-key): ")
				vaultInput, _ := reader.ReadString('\n')
				vaultInput = strings.TrimSpace(vaultInput)

				if vaultInput != "" {
					if err := configManager.SetAPIKeyVault(vaultInput); err != nil {
						return fmt.Errorf("failed to save Vault path: %w", err)
					}
					fmt.Println(" Vault path saved to config file")
					fmt.Println(" Note: Make sure to store your API key at this Vault path")
				}

			case "c":
				fmt.Println(" Skipping API key configuration")
				fmt.Println("   Set one of these environment variables:")
				if selectedProvider == "azure-openai" {
					fmt.Println("   - AZURE_OPENAI_API_KEY")
					fmt.Println("   - OPENAI_API_KEY")
				} else {
					fmt.Println("   - ANTHROPIC_API_KEY")
					fmt.Println("   - CLAUDE_API_KEY")
				}
				fmt.Println("   - AI_API_KEY")
			}

			// Azure OpenAI specific configuration
			if selectedProvider == "azure-openai" {
				fmt.Println("\n3. Azure OpenAI Configuration")

				fmt.Print("Enter your Azure OpenAI endpoint (e.g., https://myresource.openai.azure.com): ")
				endpointInput, _ := reader.ReadString('\n')
				endpointInput = strings.TrimSpace(endpointInput)

				if endpointInput != "" {
					updates := map[string]any{"azure_endpoint": endpointInput}
					if err := configManager.UpdateConfig(updates); err != nil {
						return fmt.Errorf("failed to save Azure endpoint: %w", err)
					}
					fmt.Println(" Azure endpoint saved")
				}

				fmt.Print("Enter your deployment name (e.g., gpt-4): ")
				deploymentInput, _ := reader.ReadString('\n')
				deploymentInput = strings.TrimSpace(deploymentInput)

				if deploymentInput != "" {
					updates := map[string]any{"azure_deployment": deploymentInput}
					if err := configManager.UpdateConfig(updates); err != nil {
						return fmt.Errorf("failed to save Azure deployment: %w", err)
					}
					fmt.Println(" Azure deployment saved")
				}

				fmt.Print("Enter API version (press Enter for default 2024-02-15-preview): ")
				versionInput, _ := reader.ReadString('\n')
				versionInput = strings.TrimSpace(versionInput)

				if versionInput != "" {
					updates := map[string]any{"azure_api_version": versionInput}
					if err := configManager.UpdateConfig(updates); err != nil {
						return fmt.Errorf("failed to save Azure API version: %w", err)
					}
					fmt.Printf(" Azure API version set to: %s\n", versionInput)
				}
			}

			// Model selection
			fmt.Print("\nSelect AI model (press Enter for default): ")
			modelInput, _ := reader.ReadString('\n')
			modelInput = strings.TrimSpace(modelInput)

			if modelInput != "" {
				updates := map[string]any{"model": modelInput}
				if err := configManager.UpdateConfig(updates); err != nil {
					return fmt.Errorf("failed to update model: %w", err)
				}
				fmt.Printf(" Model set to: %s\n", modelInput)
			}

			fmt.Println("\n Configuration complete!")
			fmt.Println("You can now use 'eos ai ask' and other AI commands.")
			return nil
		}

		// Non-interactive mode - apply flags
		updates := make(map[string]any)

		if provider != "" {
			updates["provider"] = provider
			fmt.Printf(" Provider set to: %s\n", provider)
		}

		if apiKey != "" {
			if err := ai.ValidateAPIKey(apiKey); err != nil {
				fmt.Printf(" Warning: %v\n", err)
			}
			if err := configManager.SetAPIKey(apiKey); err != nil {
				return fmt.Errorf("failed to save API key: %w", err)
			}
			fmt.Println(" API key saved")
		}

		if vaultPath != "" {
			if err := configManager.SetAPIKeyVault(vaultPath); err != nil {
				return fmt.Errorf("failed to save Vault path: %w", err)
			}
			fmt.Println(" Vault path saved")
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
			fmt.Println(" Configuration updated")
		}

		return nil
	}),
}

// Helper functions

func containsTechnicalTerms(text string) bool {
	technicalTerms := []string{
		"docker", "compose", "container", "terraform", "vault", "consul",
		"k3s", "kubernetes", "service", "config", "log", "error", "fail",
		"port", "network", "ssl", "tls", "certificate", "nginx", "apache",
	}

	lowText := strings.ToLower(text)
	for _, term := range technicalTerms {
		if strings.Contains(lowText, term) {
			return true
		}
	}
	return false
}

func displayEnvironmentAnalysis(env *ai.EnvironmentContext, detailed bool) {
	fmt.Println(" Environment Analysis Results")
	fmt.Println(strings.Repeat("-", 40))

	// File System Analysis
	if env.FileSystem != nil {
		fs := env.FileSystem
		fmt.Printf(" Files Found:\n")
		if len(fs.ComposeFiles) > 0 {
			fmt.Printf("    Docker Compose: %d files\n", len(fs.ComposeFiles))
			if detailed {
				for _, file := range fs.ComposeFiles {
					fmt.Printf("      - %s (modified: %s)\n", file.Path, file.ModTime.Format("2006-01-02 15:04"))
				}
			}
		}
		if len(fs.TerraformFiles) > 0 {
			fmt.Printf("     Terraform: %d files\n", len(fs.TerraformFiles))
			if detailed {
				for _, file := range fs.TerraformFiles {
					fmt.Printf("      - %s\n", file.Path)
				}
			}
		}
		if len(fs.ConfigFiles) > 0 {
			fmt.Printf("     Configuration: %d files\n", len(fs.ConfigFiles))
		}
		fmt.Println()
	}

	// Services Analysis
	if env.Services != nil {
		services := env.Services
		fmt.Printf(" Services:\n")
		if len(services.DockerContainers) > 0 {
			fmt.Printf("    Docker Containers: %d\n", len(services.DockerContainers))
			if detailed {
				for _, container := range services.DockerContainers {
					fmt.Printf("      - %s: %s (%s)\n", container.Name, container.Status, container.Image)
				}
			}
		}
		if len(services.SystemdServices) > 0 {
			fmt.Printf("     Systemd Services: %d\n", len(services.SystemdServices))
		}
		if len(services.NetworkPorts) > 0 {
			fmt.Printf("   🌐 Listening Ports: %d\n", len(services.NetworkPorts))
		}
		fmt.Println()
	}

	// Infrastructure Status
	if env.Infrastructure != nil {
		infra := env.Infrastructure
		fmt.Printf("  Infrastructure:\n")
		if infra.VaultStatus != nil {
			status := " Unavailable"
			if infra.VaultStatus.Initialized {
				if infra.VaultStatus.Sealed {
					status = " Sealed"
				} else {
					status = " Ready"
				}
			}
			fmt.Printf("    Vault: %s\n", status)
		}
		if infra.ConsulStatus != nil && infra.ConsulStatus.Leader != "" {
			fmt.Printf("    Consul:  Ready (leader: %s)\n", infra.ConsulStatus.Leader)
		}
		fmt.Println()
	}

	// Recent Issues
	if env.Logs != nil && len(env.Logs.ErrorLogs) > 0 {
		fmt.Printf(" Recent Issues: %d errors found\n", len(env.Logs.ErrorLogs))
		if detailed {
			for i, log := range env.Logs.ErrorLogs {
				if i >= 5 {
					fmt.Printf("      ... and %d more\n", len(env.Logs.ErrorLogs)-5)
					break
				}
				fmt.Printf("      - [%s] %s\n", log.Service, log.Message[:min(80, len(log.Message))])
			}
		}
		fmt.Println()
	}
}

func startInteractiveChat(rc *eos_io.RuntimeContext, assistant *ai.AIAssistant, ctx *ai.ConversationContext) error {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("You: ")
		input, err := reader.ReadString('\n')
		if err != nil {
			return err
		}

		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		// Check for exit commands
		if strings.ToLower(input) == "exit" || strings.ToLower(input) == "quit" || strings.ToLower(input) == "bye" {
			fmt.Println(" Goodbye! Feel free to ask for help anytime.")
			break
		}

		// Special commands
		if strings.ToLower(input) == "analyze" {
			fmt.Println(" Re-analyzing environment...")
			analyzer := ai.NewEnvironmentAnalyzer(ctx.Environment.WorkingDirectory)
			if env, err := analyzer.AnalyzeEnvironment(rc); err == nil {
				ctx.Environment = env
				fmt.Println(" Environment analysis updated.")
				continue
			}
		}

		fmt.Println(" Thinking...")

		// Get AI response
		response, err := assistant.Chat(rc, ctx, input)
		if err != nil {
			fmt.Printf(" Error: %v\n", err)
			continue
		}

		if len(response.Choices) == 0 {
			fmt.Println(" No response from AI")
			continue
		}

		fmt.Println("\n AI:")
		fmt.Println(response.Choices[0].Message.Content)
		fmt.Println()

		// Check for actions
		if actions, err := ai.ParseActionsFromResponse(response.Choices[0].Message.Content); err == nil && len(actions) > 0 {
			fmt.Printf(" I have %d suggestion(s). Type 'implement' to execute them.\n\n", len(actions))
		}
	}

	return nil
}

func implementActions(rc *eos_io.RuntimeContext, actions []*ai.Action, workingDir string, dryRun bool) error {
	if len(actions) == 0 {
		fmt.Println("No actions to implement.")
		return nil
	}

	executor := ai.NewActionExecutor(workingDir, dryRun)

	fmt.Printf(" Implementing %d action(s)...\n\n", len(actions))

	for i, action := range actions {
		fmt.Printf("Action %d/%d: %s\n", i+1, len(actions), action.Description)

		result, err := executor.ExecuteAction(rc, action)
		if err != nil {
			fmt.Printf(" Failed: %v\n", err)
			continue
		}

		if result.Success {
			fmt.Printf(" Success: %s\n", result.Message)
			if result.Output != "" {
				fmt.Printf("   Output: %s\n", result.Output)
			}
		} else {
			fmt.Printf(" Failed: %s\n", result.Message)
		}
		fmt.Println()
	}

	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// maskAPIKey masks an API key for display purposes
func maskAPIKey(apiKey string) string {
	if apiKey == "" {
		return "[not configured]"
	}

	// Show first few characters and last few characters
	if len(apiKey) > 10 {
		return apiKey[:6] + "..." + apiKey[len(apiKey)-4:]
	}

	// For shorter keys, just show partial
	if len(apiKey) > 4 {
		return apiKey[:3] + "..."
	}

	return "***"
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

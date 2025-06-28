// cmd/delphi/services/ab_config.go
package services

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ABTestConfig represents the structure from prompt-ab-tester.py
type ABTestConfig struct {
	Experiments []ABTestExperiment `json:"experiments"`
}

type ABTestExperiment struct {
	Name             string                `json:"name"`
	Description      string                `json:"description"`
	Status           string                `json:"status"` // active, paused, completed, draft
	StartDate        *string               `json:"start_date,omitempty"`
	EndDate          *string               `json:"end_date,omitempty"`
	Variants         []ABTestVariant       `json:"variants"`
	CohortStrategy   string                `json:"cohort_strategy"`   // agent_rule, agent_only, rule_only
	StickySessions   bool                  `json:"sticky_sessions"`
	TargetRules      []int                 `json:"target_rules"`      // specific rule IDs, empty = all
	MinRuleLevel     int                   `json:"min_rule_level"`
	SampleRate       float64               `json:"sample_rate"`       // 0.0-1.0
}

type ABTestVariant struct {
	Name        string                 `json:"name"`
	PromptType  string                 `json:"prompt_type"` // maps to parser_type enum
	Weight      float64                `json:"weight"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
}

// NewABConfigCmd creates enhanced A/B configuration management command
func NewABConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ab-config",
		Short: "Manage A/B testing configuration for prompt optimization",
		Long: `Enhanced A/B testing configuration management for prompt optimization.

This command provides comprehensive management of prompt A/B testing experiments
based on the sophisticated framework implemented in prompt-ab-tester.py.

Subcommands:
- create: Create new A/B testing experiments
- list: Show active and configured experiments  
- status: Show experiment status and metrics
- enable: Enable/start experiments
- disable: Pause/stop experiments
- analyze: Analyze experiment results and performance
- validate: Validate configuration syntax

Example experiment workflow:
1. Create experiment: eos delphi services ab-config create --name "security-prompt-v2"
2. Enable experiment: eos delphi services ab-config enable security-prompt-v2
3. Monitor status: eos delphi services ab-config status
4. Analyze results: eos delphi services ab-config analyze security-prompt-v2

Configuration file: /opt/delphi/ab-test-config.json`,
		Aliases: []string{"ab", "abtest"},
	}

	// Add subcommands
	cmd.AddCommand(NewABConfigCreateCmd())
	cmd.AddCommand(NewABConfigListCmd())
	cmd.AddCommand(NewABConfigStatusCmd())
	cmd.AddCommand(NewABConfigEnableCmd())
	cmd.AddCommand(NewABConfigDisableCmd())
	cmd.AddCommand(NewABConfigAnalyzeCmd())
	cmd.AddCommand(NewABConfigValidateCmd())

	return cmd
}

// NewABConfigCreateCmd creates a new A/B testing experiment
func NewABConfigCreateCmd() *cobra.Command {
	var (
		name            string
		description     string
		variantA        string
		variantB        string
		weightA         float64
		weightB         float64
		cohortStrategy  string
		sampleRate      float64
		targetRules     []int
		minRuleLevel    int
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create new A/B testing experiment",
		Long: `Create a new A/B testing experiment for prompt optimization.

Examples:
  # Create simple A/B test
  eos delphi services ab-config create \
    --name "security-analysis-v2" \
    --description "Test improved security analysis prompts" \
    --variant-a "security_analysis" \
    --variant-b "security_analysis_v2" \
    --weight-a 0.5 --weight-b 0.5

  # Create targeted test for high-priority rules
  eos delphi services ab-config create \
    --name "critical-alert-prompts" \
    --min-rule-level 10 \
    --sample-rate 0.3 \
    --cohort-strategy "agent_rule"`,
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)

			if name == "" {
				return fmt.Errorf("experiment name is required (--name)")
			}

			// Load existing configuration
			configPath := "/opt/delphi/ab-test-config.json"
			config, err := loadABTestConfig(configPath)
			if err != nil {
				logger.Warn("Creating new configuration file", zap.Error(err))
				config = &ABTestConfig{Experiments: []ABTestExperiment{}}
			}

			// Check for duplicate names
			for _, exp := range config.Experiments {
				if exp.Name == name {
					return fmt.Errorf("experiment %s already exists", name)
				}
			}

			// Create experiment variants
			variants := []ABTestVariant{}
			if variantA != "" {
				variants = append(variants, ABTestVariant{
					Name:        "variant_a",
					PromptType:  variantA,
					Weight:      weightA,
					Description: fmt.Sprintf("Variant A: %s", variantA),
					Parameters:  make(map[string]interface{}),
				})
			}
			if variantB != "" {
				variants = append(variants, ABTestVariant{
					Name:        "variant_b", 
					PromptType:  variantB,
					Weight:      weightB,
					Description: fmt.Sprintf("Variant B: %s", variantB),
					Parameters:  make(map[string]interface{}),
				})
			}

			if len(variants) == 0 {
				return fmt.Errorf("at least one variant must be specified")
			}

			// Create new experiment
			experiment := ABTestExperiment{
				Name:           name,
				Description:    description,
				Status:         "draft",
				Variants:       variants,
				CohortStrategy: cohortStrategy,
				StickySessions: true,
				TargetRules:    targetRules,
				MinRuleLevel:   minRuleLevel,
				SampleRate:     sampleRate,
			}

			// Add to configuration
			config.Experiments = append(config.Experiments, experiment)

			// Save configuration
			if err := saveABTestConfig(configPath, config); err != nil {
				return fmt.Errorf("failed to save configuration: %w", err)
			}

			logger.Info("A/B testing experiment created successfully",
				zap.String("name", name),
				zap.String("config_file", configPath),
				zap.Int("variants", len(variants)),
				zap.String("status", "draft"))

			logger.Info("Next steps",
				zap.String("enable", fmt.Sprintf("eos delphi services ab-config enable %s", name)),
				zap.String("status", "eos delphi services ab-config status"))

			return nil
		}),
	}

	cmd.Flags().StringVar(&name, "name", "", "Experiment name (required)")
	cmd.Flags().StringVar(&description, "description", "", "Experiment description")
	cmd.Flags().StringVar(&variantA, "variant-a", "", "Prompt type for variant A")
	cmd.Flags().StringVar(&variantB, "variant-b", "", "Prompt type for variant B")
	cmd.Flags().Float64Var(&weightA, "weight-a", 0.5, "Weight for variant A (0.0-1.0)")
	cmd.Flags().Float64Var(&weightB, "weight-b", 0.5, "Weight for variant B (0.0-1.0)")
	cmd.Flags().StringVar(&cohortStrategy, "cohort-strategy", "agent_rule", "Cohort assignment strategy (agent_rule, agent_only, rule_only)")
	cmd.Flags().Float64Var(&sampleRate, "sample-rate", 1.0, "Sample rate (0.0-1.0)")
	cmd.Flags().IntSliceVar(&targetRules, "target-rules", []int{}, "Target specific rule IDs (empty = all rules)")
	cmd.Flags().IntVar(&minRuleLevel, "min-rule-level", 0, "Minimum rule level for inclusion")

	return cmd
}

// NewABConfigStatusCmd shows A/B testing status and metrics
func NewABConfigStatusCmd() *cobra.Command {
	var detailed bool

	cmd := &cobra.Command{
		Use:   "status [experiment-name]",
		Short: "Show A/B testing experiment status and metrics",
		Long: `Display status and performance metrics for A/B testing experiments.

Shows:
- Experiment configuration and status
- Assignment metrics (total assignments, distribution)
- Performance metrics (success rates, response times)
- Statistical significance (if available)

Examples:
  eos delphi services ab-config status                    # All experiments
  eos delphi services ab-config status security-prompts   # Specific experiment
  eos delphi services ab-config status --detailed         # Detailed metrics`,
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)

			configPath := "/opt/delphi/ab-test-config.json"
			config, err := loadABTestConfig(configPath)
			if err != nil {
				return fmt.Errorf("failed to load A/B test configuration: %w", err)
			}

			// Filter experiments if name specified
			var experiments []ABTestExperiment
			if len(args) > 0 {
				expName := args[0]
				for _, exp := range config.Experiments {
					if exp.Name == expName {
						experiments = append(experiments, exp)
						break
					}
				}
				if len(experiments) == 0 {
					return fmt.Errorf("experiment %s not found", expName)
				}
			} else {
				experiments = config.Experiments
			}

			if len(experiments) == 0 {
				logger.Info("No A/B testing experiments configured")
				return nil
			}

			// Load metrics from metrics file
			metricsPath := "/var/log/stackstorm/ab-test-metrics.jsonl"
			metrics, err := loadABTestMetrics(metricsPath)
			if err != nil {
				logger.Warn("Failed to load metrics", zap.Error(err))
				metrics = make(map[string]interface{})
			}

			// Display experiment status
			for _, exp := range experiments {
				logger.Info(fmt.Sprintf("Experiment: %s", exp.Name),
					zap.String("description", exp.Description),
					zap.String("status", exp.Status),
					zap.Int("variants", len(exp.Variants)),
					zap.String("cohort_strategy", exp.CohortStrategy),
					zap.Float64("sample_rate", exp.SampleRate))

				if detailed {
					// Show variant details
					for _, variant := range exp.Variants {
						logger.Info(fmt.Sprintf("  Variant: %s", variant.Name),
							zap.String("prompt_type", variant.PromptType),
							zap.Float64("weight", variant.Weight),
							zap.String("description", variant.Description))
					}

					// Show metrics if available
					if variantMetrics, exists := metrics["variant_metrics"]; exists {
						if vm, ok := variantMetrics.(map[string]interface{}); ok {
							for variantKey, metrics := range vm {
								if strings.Contains(variantKey, exp.Name) {
									logger.Info(fmt.Sprintf("  Metrics: %s", variantKey),
										zap.Any("metrics", metrics))
								}
							}
						}
					}
				}
			}

			return nil
		}),
	}

	cmd.Flags().BoolVar(&detailed, "detailed", false, "Show detailed metrics")
	return cmd
}

// Helper functions for A/B testing configuration management

func loadABTestConfig(path string) (*ABTestConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config ABTestConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("invalid JSON in %s: %w", path, err)
	}

	return &config, nil
}

func saveABTestConfig(path string, config *ABTestConfig) error {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal configuration: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write configuration file: %w", err)
	}

	return nil
}

func loadABTestMetrics(path string) (map[string]interface{}, error) {
	// Load the most recent metrics from JSONL file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 || lines[len(lines)-1] == "" {
		if len(lines) > 1 {
			lines = lines[:len(lines)-1]
		}
	}

	if len(lines) == 0 {
		return make(map[string]interface{}), nil
	}

	// Parse the last (most recent) metrics entry
	var metrics map[string]interface{}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &metrics); err != nil {
		return nil, fmt.Errorf("failed to parse metrics: %w", err)
	}

	return metrics, nil
}

// Placeholder implementations for other subcommands
func NewABConfigListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all A/B testing experiments",
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			return fmt.Errorf("not yet implemented - use 'status' command for now")
		}),
	}
}

func NewABConfigEnableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "enable <experiment-name>",
		Short: "Enable/start an A/B testing experiment",
		Args:  cobra.ExactArgs(1),
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			return fmt.Errorf("not yet implemented")
		}),
	}
}

func NewABConfigDisableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disable <experiment-name>",
		Short: "Disable/pause an A/B testing experiment",
		Args:  cobra.ExactArgs(1),
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			return fmt.Errorf("not yet implemented")
		}),
	}
}

func NewABConfigAnalyzeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "analyze <experiment-name>",
		Short: "Analyze A/B testing experiment results",
		Args:  cobra.ExactArgs(1),
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			return fmt.Errorf("not yet implemented")
		}),
	}
}

func NewABConfigValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Validate A/B testing configuration syntax",
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			configPath := "/opt/delphi/ab-test-config.json"
			_, err := loadABTestConfig(configPath)
			if err != nil {
				return fmt.Errorf("configuration validation failed: %w", err)
			}
			
			logger := otelzap.Ctx(rc.Ctx)
			logger.Info("A/B testing configuration is valid", zap.String("config_file", configPath))
			return nil
		}),
	}
}
package services

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi_channels"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewFixChannelsCmd creates the fix-channels command
func NewFixChannelsCmd() *cobra.Command {
	var (
		workersDir    string
		outputJSON    bool
		dryRun        bool
		createBackups bool
		analyze       bool
	)

	cmd := &cobra.Command{
		Use:   "fix-channels",
		Short: "Standardize PostgreSQL notification channels for Delphi workers",
		Long: `Standardizes PostgreSQL notification channels across all Delphi workers to ensure
consistent communication in the pipeline.

This command:
- Updates LISTEN_CHANNEL and NOTIFY_CHANNEL variable definitions
- Fixes pg_notify() function calls to use correct channels
- Updates LISTEN statements in SQL code
- Creates backups of modified files (unless disabled)
- Validates the entire notification flow

Standard notification flow:
  new_alert       → delphi-listener → delphi-agent-enricher
  agent_enriched  → delphi-agent-enricher → llm-worker  
  new_response    → llm-worker → email-structurer
  alert_structured → email-structurer → email-formatter
  alert_formatted → email-formatter → email-sender
  alert_sent      → email-sender → final (archive/metrics)`,
		Example: `  # Fix channels in default directory
  eos delphi services fix-channels

  # Analyze current configuration without making changes
  eos delphi services fix-channels --analyze

  # Fix channels with custom workers directory
  eos delphi services fix-channels --workers-dir /custom/path

  # Dry run to see what would be changed
  eos delphi services fix-channels --dry-run

  # Output results in JSON format
  eos delphi services fix-channels --json

  # Fix without creating backups
  eos delphi services fix-channels --no-backups`,
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			
			logger.Info("Starting notification channel standardization",
				zap.String("workers_dir", workersDir),
				zap.Bool("dry_run", dryRun),
				zap.Bool("analyze_only", analyze),
				zap.Bool("create_backups", createBackups))

			// Create configuration
			config := &delphi_channels.ChannelStandardizerConfig{
				WorkersDir:    workersDir,
				CreateBackups: createBackups,
				DryRun:        dryRun,
				ExcludePatterns: []string{"*.bak", "*.old", "__pycache__", ".git"},
			}

			// Create standardizer
			standardizer := delphi_channels.NewChannelStandardizer(config)

			if analyze {
				return runAnalysis(standardizer, outputJSON, logger)
			} else {
				return runStandardization(standardizer, outputJSON, dryRun, logger)
			}
		}),
	}

	cmd.Flags().StringVar(&workersDir, "workers-dir", "/opt/stackstorm/packs/delphi/actions/python_workers", 
		"Directory containing Delphi worker Python files")
	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output results in JSON format")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be changed without making modifications")
	cmd.Flags().BoolVar(&createBackups, "backups", true, "Create backup files before modification")
	cmd.Flags().BoolVar(&analyze, "analyze", false, "Analyze current configuration without making changes")
	
	// Create alias for --no-backups
	cmd.Flags().BoolVar(&createBackups, "no-backups", true, "Disable backup creation")
	cmd.Flag("no-backups").NoOptDefVal = "false"

	return cmd
}

// runAnalysis analyzes worker configurations without making changes
func runAnalysis(standardizer *delphi_channels.ChannelStandardizer, outputJSON bool, logger otelzap.LoggerWithCtx) error {
	logger.Info("Analyzing current worker channel configurations")

	infos, err := standardizer.AnalyzeWorkers()
	if err != nil {
		logger.Error("Failed to analyze workers", zap.Error(err))
		return fmt.Errorf("analysis failed: %v", err)
	}

	if outputJSON {
		return outputWorkerAnalysisJSON(infos)
	} else {
		return outputWorkerAnalysisText(infos)
	}
}

// runStandardization performs channel standardization
func runStandardization(standardizer *delphi_channels.ChannelStandardizer, outputJSON, dryRun bool, logger otelzap.LoggerWithCtx) error {
	if dryRun {
		logger.Info("Running in dry-run mode - no changes will be made")
	} else {
		logger.Info("Standardizing notification channels")
	}

	result := standardizer.StandardizeAll()

	if outputJSON {
		return outputStandardizationJSON(result)
	} else {
		return outputStandardizationText(result, dryRun)
	}
}

// outputWorkerAnalysisJSON outputs worker analysis in JSON format
func outputWorkerAnalysisJSON(infos []delphi_channels.WorkerChannelInfo) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(map[string]interface{}{
		"analysis": infos,
		"standard_channels": delphi_channels.StandardChannels,
	})
}

// outputWorkerAnalysisText outputs worker analysis in human-readable format
func outputWorkerAnalysisText(infos []delphi_channels.WorkerChannelInfo) error {
	fmt.Println("📡 Delphi Notification Channel Analysis")
	fmt.Println(strings.Repeat("=", 50))

	correctCount := 0
	for _, info := range infos {
		fmt.Printf("\n📄 %s\n", info.Filename)
		
		if info.IsCorrect {
			fmt.Println("   ✅ Configuration is correct")
			correctCount++
		} else {
			fmt.Println("   ❌ Configuration needs fixing")
		}

		if len(info.ListenChannels) > 0 {
			fmt.Printf("   📥 Listen: %s\n", strings.Join(info.ListenChannels, ", "))
		}
		
		if len(info.NotifyChannels) > 0 {
			fmt.Printf("   📤 Notify: %s\n", strings.Join(info.NotifyChannels, ", "))
		}

		if len(info.Issues) > 0 {
			fmt.Println("   🔍 Issues:")
			for _, issue := range info.Issues {
				fmt.Printf("      • %s\n", issue)
			}
		}
	}

	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Printf("📊 Summary: %d/%d workers correctly configured\n", correctCount, len(infos))

	if correctCount < len(infos) {
		fmt.Println("\n💡 To fix issues, run: eos delphi services fix-channels")
	}

	fmt.Println("\n📡 STANDARD NOTIFICATION FLOW:")
	for channel, description := range delphi_channels.StandardChannels {
		fmt.Printf("   %-18s → %s\n", channel, description)
	}
	fmt.Println(strings.Repeat("=", 50))

	return nil
}

// outputStandardizationJSON outputs standardization results in JSON format
func outputStandardizationJSON(result *delphi_channels.StandardizationResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

// outputStandardizationText outputs standardization results in human-readable format
func outputStandardizationText(result *delphi_channels.StandardizationResult, dryRun bool) error {
	if dryRun {
		fmt.Println("🔍 Notification Channel Standardization (DRY RUN)")
	} else {
		fmt.Println("🔧 Notification Channel Standardization")
	}
	fmt.Println(strings.Repeat("=", 50))

	// Show changes
	if len(result.Changes) > 0 {
		if dryRun {
			fmt.Printf("\n📋 CHANGES THAT WOULD BE MADE (%d):\n", len(result.Changes))
		} else {
			fmt.Printf("\n✅ CHANGES MADE (%d):\n", len(result.Changes))
		}
		
		changesByFile := groupChangesByFile(result.Changes)
		for file, changes := range changesByFile {
			fmt.Printf("   📄 %s:\n", file)
			for _, change := range changes {
				fmt.Printf("      %s: %s → %s\n", 
					getChangeTypeEmoji(change.Type), 
					change.OldValue, 
					change.NewValue)
			}
		}
	}

	// Show files updated
	if len(result.FilesUpdated) > 0 {
		if dryRun {
			fmt.Printf("\n📁 FILES THAT WOULD BE UPDATED (%d):\n", len(result.FilesUpdated))
		} else {
			fmt.Printf("\n📁 FILES UPDATED (%d):\n", len(result.FilesUpdated))
		}
		for _, file := range result.FilesUpdated {
			fmt.Printf("   ✓ %s\n", file)
		}
	}

	// Show files skipped
	if len(result.FilesSkipped) > 0 {
		fmt.Printf("\n⏭️  FILES SKIPPED (%d):\n", len(result.FilesSkipped))
		for _, file := range result.FilesSkipped {
			fmt.Printf("   • %s\n", file)
		}
	}

	// Show backups created
	if len(result.BackupsCreated) > 0 && !dryRun {
		fmt.Printf("\n💾 BACKUPS CREATED (%d):\n", len(result.BackupsCreated))
		for _, backup := range result.BackupsCreated {
			fmt.Printf("   💾 %s\n", backup)
		}
	}

	// Show errors
	if len(result.Errors) > 0 {
		fmt.Printf("\n❌ ERRORS (%d):\n", len(result.Errors))
		for _, err := range result.Errors {
			fmt.Printf("   • %s\n", err)
		}
	}

	// Summary
	fmt.Println("\n" + strings.Repeat("=", 50))
	
	if result.Success {
		if len(result.Changes) == 0 {
			fmt.Println("✅ All workers already use correct notification channels!")
		} else if dryRun {
			fmt.Printf("🔍 Analysis complete: %d changes needed\n", len(result.Changes))
			fmt.Println("💡 Run without --dry-run to apply changes")
		} else {
			fmt.Printf("✅ Standardization complete: %d changes applied\n", len(result.Changes))
		}
	} else {
		fmt.Println("❌ Standardization completed with errors")
		if !dryRun {
			os.Exit(1)
		}
	}

	if !dryRun && len(result.Changes) == 0 {
		fmt.Println("\n📡 STANDARD NOTIFICATION FLOW:")
		for channel, description := range delphi_channels.StandardChannels {
			fmt.Printf("   %-18s → %s\n", channel, description)
		}
	}

	fmt.Println(strings.Repeat("=", 50))
	return nil
}

// Helper functions
func groupChangesByFile(changes []delphi_channels.ChannelChange) map[string][]delphi_channels.ChannelChange {
	grouped := make(map[string][]delphi_channels.ChannelChange)
	for _, change := range changes {
		filename := change.File
		if strings.Contains(filename, "/") {
			// Extract just the filename from the path
			parts := strings.Split(filename, "/")
			filename = parts[len(parts)-1]
		}
		grouped[filename] = append(grouped[filename], change)
	}
	return grouped
}

func getChangeTypeEmoji(changeType string) string {
	switch changeType {
	case "listen_channel":
		return "📥"
	case "notify_channel":
		return "📤"
	case "pg_notify":
		return "🔔"
	case "listen_statement":
		return "👂"
	default:
		return "🔧"
	}
}
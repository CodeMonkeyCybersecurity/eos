package promote

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environments"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/verify"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/promotion"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var historyCmd = &cobra.Command{
	Use:   "history [component-name]",
	Short: "View promotion history and audit trails",
	Long: `View comprehensive promotion history and audit trails for components and environments.

The history command provides detailed visibility into promotion activities, compliance
tracking, and deployment patterns. It supports various filtering and formatting options
to help with debugging, compliance reporting, and operational analysis.

History features include:
- Complete promotion audit trails with timestamps and actors
- Component-specific and environment-specific filtering
- Success/failure analysis with error details
- Rollback tracking and correlation
- Performance metrics and deployment patterns
- Export capabilities for compliance reporting
- Integration with external audit systems

Examples:
  # View all promotion history
  eos promote history

  # View history for specific component
  eos promote history helen

  # View promotions to production environment
  eos promote history --environment production

  # View failed promotions only
  eos promote history --status failed

  # View promotions in date range
  eos promote history --since 2024-01-01 --until 2024-01-31

  # Export history to JSON
  eos promote history helen --format json --output helen-history.json`,
	Args: cobra.MaximumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// CRITICAL: Detect flag-like args (P0-1 fix)
		if err := verify.ValidateNoFlagLikeArgs(args); err != nil {
			return err
		}

		var componentName string
		if len(args) > 0 {
			componentName = args[0]
		}

		logger.Info("Viewing promotion history",
			zap.String("command", "promote history"),
			zap.String("component", componentName),
			zap.String("context", rc.Component))

		// Parse flags
		environment, _ := cmd.Flags().GetString("environment")
		status, _ := cmd.Flags().GetString("status")
		since, _ := cmd.Flags().GetString("since")
		until, _ := cmd.Flags().GetString("until")
		limit, _ := cmd.Flags().GetInt("limit")
		format, _ := cmd.Flags().GetString("format")
		output, _ := cmd.Flags().GetString("output")
		includeRollbacks, _ := cmd.Flags().GetBool("include-rollbacks")
		showDetails, _ := cmd.Flags().GetBool("details")
		groupBy, _ := cmd.Flags().GetString("group-by")

		logger.Debug("History query configuration",
			zap.String("component", componentName),
			zap.String("environment", environment),
			zap.String("status", status),
			zap.String("since", since),
			zap.String("until", until),
			zap.Int("limit", limit),
			zap.String("format", format),
			zap.Bool("include_rollbacks", includeRollbacks),
			zap.Bool("show_details", showDetails))

		// Create environment manager
		envManager, err := environments.NewEnvironmentManager("")
		if err != nil {
			logger.Error("Failed to create environment manager", zap.Error(err))
			return fmt.Errorf("failed to create environment manager: %w", err)
		}

		// Create promotion manager
		promotionConfig := &promotion.PromotionConfig{}
		_, err = promotion.NewPromotionManager(envManager, promotionConfig)
		if err != nil {
			logger.Error("Failed to create promotion manager", zap.Error(err))
			return fmt.Errorf("failed to create promotion manager: %w", err)
		}

		// Parse date filters
		var sinceTime, untilTime *time.Time
		if since != "" {
			t, err := time.Parse("2006-01-02", since)
			if err != nil {
				return fmt.Errorf("invalid since date format (use YYYY-MM-DD): %w", err)
			}
			sinceTime = &t
		}
		if until != "" {
			t, err := time.Parse("2006-01-02", until)
			if err != nil {
				return fmt.Errorf("invalid until date format (use YYYY-MM-DD): %w", err)
			}
			// Set to end of day
			t = t.Add(23*time.Hour + 59*time.Minute + 59*time.Second)
			untilTime = &t
		}

		// Get promotion history
		historyFilter := promotion.HistoryFilter{
			Component:        componentName,
			Environment:      environment,
			Status:           status,
			Since:            sinceTime,
			Until:            untilTime,
			Limit:            limit,
			IncludeRollbacks: includeRollbacks,
		}

		history, err := promotion.GetPromotionHistory(rc, historyFilter)
		if err != nil {
			logger.Error("Failed to get promotion history", zap.Error(err))
			return fmt.Errorf("failed to get promotion history: %w", err)
		}

		// Handle different output formats
		switch format {
		case "json":
			return promotion.DisplayHistoryJSON(history, output)
		case "csv":
			return promotion.DisplayHistoryCSV(history, output)
		case "summary":
			return promotion.DisplayHistorySummary(history)
		default:
			return promotion.DisplayHistoryTable(history, showDetails, groupBy)
		}
	}),
}

func init() {
	PromoteCmd.AddCommand(historyCmd)

	// Filter flags
	historyCmd.Flags().String("environment", "", "Filter by target environment")
	historyCmd.Flags().String("status", "", "Filter by promotion status (pending, approved, completed, failed)")
	historyCmd.Flags().String("since", "", "Show promotions since date (YYYY-MM-DD)")
	historyCmd.Flags().String("until", "", "Show promotions until date (YYYY-MM-DD)")
	historyCmd.Flags().Int("limit", 50, "Maximum number of records to show")

	// Display options
	historyCmd.Flags().String("format", "table", "Output format (table, json, csv, summary)")
	historyCmd.Flags().String("output", "", "Output file (stdout if not specified)")
	historyCmd.Flags().Bool("details", false, "Show detailed information for each promotion")
	historyCmd.Flags().String("group-by", "", "Group results by (component, environment, date)")
	historyCmd.Flags().Bool("include-rollbacks", false, "Include rollback operations in history")

	// Analysis flags
	historyCmd.Flags().Bool("stats", false, "Show promotion statistics")
	historyCmd.Flags().Bool("trends", false, "Show promotion trends over time")
	historyCmd.Flags().Bool("failures", false, "Show only failed promotions with error analysis")

	historyCmd.Example = `  # View recent promotion history
  eos promote history --limit 20

  # View history for specific component
  eos promote history helen --details

  # View production promotions only
  eos promote history --environment production

  # View failed promotions
  eos promote history --status failed --details

  # View promotions in date range
  eos promote history --since 2024-01-01 --until 2024-01-31

  # Export to JSON
  eos promote history --format json --output history.json

  # Show summary statistics
  eos promote history --format summary --stats`
}

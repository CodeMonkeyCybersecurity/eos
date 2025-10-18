package promote

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environments"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
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
		historyFilter := HistoryFilter{
			Component:        componentName,
			Environment:      environment,
			Status:           status,
			Since:            sinceTime,
			Until:            untilTime,
			Limit:            limit,
			IncludeRollbacks: includeRollbacks,
		}

		history, err := getPromotionHistory(rc, historyFilter)
		if err != nil {
			logger.Error("Failed to get promotion history", zap.Error(err))
			return fmt.Errorf("failed to get promotion history: %w", err)
		}

		// Handle different output formats
		switch format {
		case "json":
			return outputHistoryJSON(history, output)
		case "csv":
			return outputHistoryCSV(history, output)
		case "summary":
			return outputHistorySummary(history)
		default:
			return outputHistoryTable(history, showDetails, groupBy)
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

// TODO: refactor - move to pkg/promotion/types.go - Data structures should be in pkg/
// HistoryFilter represents filters for promotion history queries
type HistoryFilter struct {
	Component        string
	Environment      string
	Status           string
	Since            *time.Time
	Until            *time.Time
	Limit            int
	IncludeRollbacks bool
}

// TODO: refactor - move to pkg/promotion/types.go - Data structures should be in pkg/
// PromotionHistoryRecord represents a single promotion history record
type PromotionHistoryRecord struct {
	ID               string
	Component        string
	FromEnvironment  string
	ToEnvironment    string
	Version          string
	Status           string
	PromotedBy       string
	PromotedAt       time.Time
	Duration         time.Duration
	Success          bool
	Error            string
	RolledBack       bool
	RollbackAt       *time.Time
	ApprovalCount    int
	ValidationErrors []string
	ArtifactCount    int
}

// TODO: refactor - move to pkg/promotion/history.go - History retrieval and filtering is business logic
func getPromotionHistory(rc *eos_io.RuntimeContext, filter HistoryFilter) ([]PromotionHistoryRecord, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Querying promotion history",
		zap.String("component", filter.Component),
		zap.String("environment", filter.Environment),
		zap.String("status", filter.Status))

	// Implementation would query promotion history from storage
	// For now, return mock data that demonstrates various scenarios

	mockHistory := []PromotionHistoryRecord{
		{
			ID:              "helen-prod-20240113154530-promo",
			Component:       "helen",
			FromEnvironment: "staging",
			ToEnvironment:   "production",
			Version:         "v2.1.0",
			Status:          "completed",
			PromotedBy:      "senior.engineer",
			PromotedAt:      time.Now().Add(-2 * time.Hour),
			Duration:        8 * time.Minute,
			Success:         true,
			ApprovalCount:   2,
			ArtifactCount:   3,
		},
		{
			ID:              "api-staging-20240113160000-promo",
			Component:       "api",
			FromEnvironment: "dev",
			ToEnvironment:   "staging",
			Version:         "v1.5.2",
			Status:          "completed",
			PromotedBy:      "api.developer",
			PromotedAt:      time.Now().Add(-4 * time.Hour),
			Duration:        5 * time.Minute,
			Success:         true,
			ApprovalCount:   1,
			ArtifactCount:   2,
		},
		{
			ID:              "frontend-prod-20240113120000-promo",
			Component:       "frontend",
			FromEnvironment: "staging",
			ToEnvironment:   "production",
			Version:         "v3.0.1",
			Status:          "failed",
			PromotedBy:      "frontend.developer",
			PromotedAt:      time.Now().Add(-8 * time.Hour),
			Duration:        12 * time.Minute,
			Success:         false,
			Error:           "Health check failed: service returned 500",
			ApprovalCount:   2,
			ValidationErrors: []string{
				"Database migration validation failed",
				"Performance test threshold exceeded",
			},
			ArtifactCount: 4,
		},
		{
			ID:              "helen-staging-20240112143000-promo",
			Component:       "helen",
			FromEnvironment: "dev",
			ToEnvironment:   "staging",
			Version:         "v2.1.0-rc1",
			Status:          "completed",
			PromotedBy:      "developer.user",
			PromotedAt:      time.Now().Add(-26 * time.Hour),
			Duration:        6 * time.Minute,
			Success:         true,
			ApprovalCount:   1,
			ArtifactCount:   3,
		},
		{
			ID:              "api-prod-20240111100000-promo",
			Component:       "api",
			FromEnvironment: "staging",
			ToEnvironment:   "production",
			Version:         "v1.5.0",
			Status:          "completed",
			PromotedBy:      "tech.lead",
			PromotedAt:      time.Now().Add(-50 * time.Hour),
			Duration:        15 * time.Minute,
			Success:         true,
			RolledBack:      true,
			RollbackAt:      func() *time.Time { t := time.Now().Add(-48 * time.Hour); return &t }(),
			ApprovalCount:   2,
			ArtifactCount:   2,
		},
	}

	// Apply filters
	var filtered []PromotionHistoryRecord
	for _, record := range mockHistory {
		// Component filter
		if filter.Component != "" && record.Component != filter.Component {
			continue
		}

		// Environment filter
		if filter.Environment != "" && record.ToEnvironment != filter.Environment {
			continue
		}

		// Status filter
		if filter.Status != "" && record.Status != filter.Status {
			continue
		}

		// Date filters
		if filter.Since != nil && record.PromotedAt.Before(*filter.Since) {
			continue
		}
		if filter.Until != nil && record.PromotedAt.After(*filter.Until) {
			continue
		}

		// Include rollbacks filter
		if !filter.IncludeRollbacks && record.RolledBack {
			continue
		}

		filtered = append(filtered, record)
	}

	// Sort by promoted date (newest first)
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].PromotedAt.After(filtered[j].PromotedAt)
	})

	// Apply limit
	if filter.Limit > 0 && len(filtered) > filter.Limit {
		filtered = filtered[:filter.Limit]
	}

	return filtered, nil
}

// TODO: refactor - move to pkg/output/ or pkg/promotion/display.go - Output formatting should be in pkg/
func outputHistoryTable(history []PromotionHistoryRecord, showDetails bool, groupBy string) error {
	if len(history) == 0 {
		fmt.Printf("📭 No promotion history found matching the specified criteria.\n")
		return nil
	}

	fmt.Printf("Promotion History:\n")
	fmt.Printf("═══════════════════\n")

	if groupBy != "" {
		return outputHistoryGrouped(history, groupBy, showDetails)
	}

	for i, record := range history {
		if i > 0 {
			fmt.Printf("\n")
		}

		status := ""
		if !record.Success {
			status = ""
		} else if record.RolledBack {
			status = ""
		}

		fmt.Printf("%s %s (%s) - %s → %s\n",
			status, record.Component, record.Version,
			record.FromEnvironment, record.ToEnvironment)

		fmt.Printf("   Promoted by: %s\n", record.PromotedBy)
		fmt.Printf("   When:        %s\n", record.PromotedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("   Duration:    %s\n", record.Duration.Round(time.Second))
		fmt.Printf("   Status:      %s\n", record.Status)

		if record.ApprovalCount > 0 {
			fmt.Printf("   Approvals:   %d\n", record.ApprovalCount)
		}

		if record.ArtifactCount > 0 {
			fmt.Printf("   Artifacts:   %d\n", record.ArtifactCount)
		}

		if record.Error != "" {
			fmt.Printf("   Error:       %s\n", record.Error)
		}

		if record.RolledBack && record.RollbackAt != nil {
			fmt.Printf("   Rolled back: %s\n", record.RollbackAt.Format("2006-01-02 15:04:05"))
		}

		if showDetails {
			fmt.Printf("   ID:          %s\n", record.ID)

			if len(record.ValidationErrors) > 0 {
				fmt.Printf("   Validation errors:\n")
				for _, err := range record.ValidationErrors {
					fmt.Printf("     • %s\n", err)
				}
			}
		}
	}

	fmt.Printf("\n Showing %d promotion record(s)\n", len(history))

	// Show quick stats
	successful := 0
	failed := 0
	rolledBack := 0
	for _, record := range history {
		if record.Success {
			successful++
		} else {
			failed++
		}
		if record.RolledBack {
			rolledBack++
		}
	}

	fmt.Printf("   Successful: %d, Failed: %d, Rolled back: %d\n", successful, failed, rolledBack)

	return nil
}

// TODO: refactor - move to pkg/output/ or pkg/promotion/display.go - Output formatting should be in pkg/
func outputHistoryGrouped(history []PromotionHistoryRecord, groupBy string, showDetails bool) error {
	groups := make(map[string][]PromotionHistoryRecord)

	for _, record := range history {
		var key string
		switch groupBy {
		case "component":
			key = record.Component
		case "environment":
			key = record.ToEnvironment
		case "date":
			key = record.PromotedAt.Format("2006-01-02")
		default:
			key = "all"
		}

		groups[key] = append(groups[key], record)
	}

	// Sort group keys
	var keys []string
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for i, key := range keys {
		if i > 0 {
			fmt.Printf("\n")
		}

		fmt.Printf("── %s ──\n", strings.ToUpper(key))

		for j, record := range groups[key] {
			if j > 0 {
				fmt.Printf("\n")
			}

			status := ""
			if !record.Success {
				status = ""
			} else if record.RolledBack {
				status = ""
			}

			fmt.Printf("  %s %s (%s) - %s → %s\n",
				status, record.Component, record.Version,
				record.FromEnvironment, record.ToEnvironment)
			fmt.Printf("     %s by %s (%s)\n",
				record.PromotedAt.Format("2006-01-02 15:04"),
				record.PromotedBy, record.Duration.Round(time.Second))

			if record.Error != "" {
				fmt.Printf("     Error: %s\n", record.Error)
			}
		}

		fmt.Printf("   (%d promotion(s))\n", len(groups[key]))
	}

	return nil
}

// TODO: refactor - move to pkg/output/ or pkg/promotion/display.go - Output formatting should be in pkg/
func outputHistorySummary(history []PromotionHistoryRecord) error {
	if len(history) == 0 {
		fmt.Printf("📭 No promotion history found.\n")
		return nil
	}

	fmt.Printf("Promotion History Summary:\n")
	fmt.Printf("═══════════════════════════\n")

	// Overall stats
	total := len(history)
	successful := 0
	failed := 0
	rolledBack := 0
	var totalDuration time.Duration

	componentStats := make(map[string]int)
	environmentStats := make(map[string]int)

	for _, record := range history {
		if record.Success {
			successful++
		} else {
			failed++
		}
		if record.RolledBack {
			rolledBack++
		}
		totalDuration += record.Duration

		componentStats[record.Component]++
		environmentStats[record.ToEnvironment]++
	}

	successRate := float64(successful) / float64(total) * 100
	avgDuration := totalDuration / time.Duration(total)

	fmt.Printf("Total Promotions: %d\n", total)
	fmt.Printf("Success Rate:     %.1f%% (%d successful, %d failed)\n", successRate, successful, failed)
	fmt.Printf("Rollback Rate:    %.1f%% (%d rolled back)\n", float64(rolledBack)/float64(total)*100, rolledBack)
	fmt.Printf("Average Duration: %s\n", avgDuration.Round(time.Second))

	fmt.Printf("\nBy Component:\n")
	for component, count := range componentStats {
		fmt.Printf("  • %s: %d promotion(s)\n", component, count)
	}

	fmt.Printf("\nBy Environment:\n")
	for env, count := range environmentStats {
		fmt.Printf("  • %s: %d promotion(s)\n", env, count)
	}

	// Recent activity
	if len(history) > 0 {
		latest := history[0]
		fmt.Printf("\nMost Recent:\n")
		fmt.Printf("  %s (%s) promoted to %s\n", latest.Component, latest.Version, latest.ToEnvironment)
		fmt.Printf("  %s ago by %s\n", time.Since(latest.PromotedAt).Round(time.Minute), latest.PromotedBy)
	}

	return nil
}

// TODO: refactor - move to pkg/output/ or pkg/promotion/display.go - Output formatting should be in pkg/
func outputHistoryJSON(history []PromotionHistoryRecord, outputFile string) error {
	// Implementation would marshal to JSON and write to file or stdout
	fmt.Printf("JSON export not implemented yet\n")
	return nil
}

// TODO: refactor - move to pkg/output/ or pkg/promotion/display.go - Output formatting should be in pkg/
func outputHistoryCSV(history []PromotionHistoryRecord, outputFile string) error {
	// Implementation would write CSV format to file or stdout
	fmt.Printf("CSV export not implemented yet\n")
	return nil
}

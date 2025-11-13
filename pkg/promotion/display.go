// pkg/promotion/display.go

package promotion

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// DisplayHistoryTable outputs promotion history in table format
func DisplayHistoryTable(history []PromotionHistoryRecord, showDetails bool, groupBy string) error {
	if len(history) == 0 {
		fmt.Printf("No promotion history found matching the specified criteria.\n")
		return nil
	}

	fmt.Printf("Promotion History:\n")
	fmt.Printf("═══════════════════\n")

	if groupBy != "" {
		return DisplayHistoryGrouped(history, groupBy, showDetails)
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

// DisplayHistoryGrouped outputs promotion history grouped by a specified field
func DisplayHistoryGrouped(history []PromotionHistoryRecord, groupBy string, showDetails bool) error {
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

// DisplayHistorySummary outputs promotion history summary statistics
func DisplayHistorySummary(history []PromotionHistoryRecord) error {
	if len(history) == 0 {
		fmt.Printf("No promotion history found.\n")
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

// DisplayHistoryJSON exports promotion history to JSON format
func DisplayHistoryJSON(history []PromotionHistoryRecord, outputFile string) error {
	// TODO: Implement JSON marshaling and file output
	// Implementation would marshal to JSON and write to file or stdout
	fmt.Printf("JSON export not implemented yet\n")
	return nil
}

// DisplayHistoryCSV exports promotion history to CSV format
func DisplayHistoryCSV(history []PromotionHistoryRecord, outputFile string) error {
	// TODO: Implement CSV formatting and file output
	// Implementation would write CSV format to file or stdout
	fmt.Printf("CSV export not implemented yet\n")
	return nil
}

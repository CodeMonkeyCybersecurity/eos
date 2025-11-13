// pkg/promotion/history.go

package promotion

import (
	"sort"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// GetPromotionHistory retrieves promotion history based on provided filters
//
// This function implements the Assess → Intervene → Evaluate pattern:
// - Assess: Validate filter criteria and log query parameters
// - Intervene: Query promotion history from storage (currently mock data)
// - Evaluate: Apply filters, sort results, and enforce limits
func GetPromotionHistory(rc *eos_io.RuntimeContext, filter HistoryFilter) ([]PromotionHistoryRecord, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Log query parameters for debugging
	logger.Debug("Querying promotion history",
		zap.String("component", filter.Component),
		zap.String("environment", filter.Environment),
		zap.String("status", filter.Status),
		zap.Int("limit", filter.Limit),
		zap.Bool("include_rollbacks", filter.IncludeRollbacks))

	// INTERVENE - Query promotion history from storage
	// TODO: Replace with actual storage backend integration (Consul KV, database, etc.)
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

	// EVALUATE - Apply filters
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

	logger.Debug("Retrieved promotion history",
		zap.Int("total_records", len(mockHistory)),
		zap.Int("filtered_records", len(filtered)))

	return filtered, nil
}

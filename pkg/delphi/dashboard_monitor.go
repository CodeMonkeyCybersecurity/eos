/* pkg/delphi/dashboard_monitor.go */

package delphi

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DashboardMonitor provides methods to fetch pipeline monitoring data
type DashboardMonitor struct {
	db *sql.DB
}

// NewDashboardMonitor creates a new dashboard monitor instance
func NewDashboardMonitor(db *sql.DB) *DashboardMonitor {
	return &DashboardMonitor{
		db: db,
	}
}

// GetPipelineHealth fetches current pipeline health from the database view
func (dm *DashboardMonitor) GetPipelineHealth(rc *eos_io.RuntimeContext) ([]PipelineHealth, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Fetching pipeline health data")

	query := `
		SELECT 
			state,
			count,
			avg_age_seconds,
			health_status,
			oldest_timestamp
		FROM pipeline_health
		ORDER BY 
			CASE state
				WHEN 'new' THEN 1
				WHEN 'enriched' THEN 2
				WHEN 'analyzed' THEN 3
				WHEN 'structured' THEN 4
				WHEN 'formatted' THEN 5
				WHEN 'sent' THEN 6
				WHEN 'failed' THEN 7
				WHEN 'archived' THEN 8
				ELSE 9
			END
	`

	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	defer cancel()

	rows, err := dm.db.QueryContext(ctx, query)
	if err != nil {
		logger.Error(" Failed to query pipeline health",
			zap.Error(err),
			zap.String("query", query))
		return nil, fmt.Errorf("failed to query pipeline health: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			logger.Warn(" Failed to close rows", zap.Error(closeErr))
		}
	}()

	var results []PipelineHealth
	for rows.Next() {
		var ph PipelineHealth
		err := rows.Scan(
			&ph.State,
			&ph.Count,
			&ph.AvgAgeSeconds,
			&ph.HealthStatus,
			&ph.OldestTimestamp,
		)
		if err != nil {
			logger.Error(" Failed to scan pipeline health row",
				zap.Error(err))
			return nil, fmt.Errorf("failed to scan pipeline health row: %w", err)
		}
		results = append(results, ph)
	}

	if err = rows.Err(); err != nil {
		logger.Error(" Error iterating pipeline health rows",
			zap.Error(err))
		return nil, fmt.Errorf("error iterating pipeline health rows: %w", err)
	}

	logger.Info(" Pipeline health data fetched",
		zap.Int("record_count", len(results)))

	return results, nil
}

// GetPipelineBottlenecks fetches current bottlenecks from the database view
func (dm *DashboardMonitor) GetPipelineBottlenecks(rc *eos_io.RuntimeContext) ([]PipelineBottleneck, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Fetching pipeline bottleneck data")

	query := `
		SELECT 
			state,
			count,
			avg_processing_time,
			max_processing_time,
			bottleneck_severity
		FROM pipeline_bottlenecks
		ORDER BY avg_processing_time DESC
	`

	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	defer cancel()

	rows, err := dm.db.QueryContext(ctx, query)
	if err != nil {
		logger.Error(" Failed to query pipeline bottlenecks",
			zap.Error(err),
			zap.String("query", query))
		return nil, fmt.Errorf("failed to query pipeline bottlenecks: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			logger.Warn(" Failed to close rows", zap.Error(closeErr))
		}
	}()

	var results []PipelineBottleneck
	for rows.Next() {
		var pb PipelineBottleneck
		err := rows.Scan(
			&pb.State,
			&pb.Count,
			&pb.AvgProcessingTime,
			&pb.MaxProcessingTime,
			&pb.BottleneckSeverity,
		)
		if err != nil {
			logger.Error(" Failed to scan bottleneck row",
				zap.Error(err))
			return nil, fmt.Errorf("failed to scan bottleneck row: %w", err)
		}
		results = append(results, pb)
	}

	if err = rows.Err(); err != nil {
		logger.Error(" Error iterating bottleneck rows",
			zap.Error(err))
		return nil, fmt.Errorf("error iterating bottleneck rows: %w", err)
	}

	logger.Info(" Pipeline bottleneck data fetched",
		zap.Int("record_count", len(results)))

	return results, nil
}

// GetParserPerformance fetches parser performance metrics from the database view
func (dm *DashboardMonitor) GetParserPerformance(rc *eos_io.RuntimeContext) (*ParserPerformance, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Fetching parser performance data")

	query := `
		SELECT 
			parsed_count,
			successful_count,
			error_count,
			success_rate,
			avg_processing_time,
			last_parsed
		FROM parser_performance
		LIMIT 1
	`

	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	defer cancel()

	var pp ParserPerformance
	err := dm.db.QueryRowContext(ctx, query).Scan(
		&pp.ParsedCount,
		&pp.SuccessfulCount,
		&pp.ErrorCount,
		&pp.SuccessRate,
		&pp.AvgProcessingTime,
		&pp.LastParsed,
	)

	if err == sql.ErrNoRows {
		logger.Warn(" No parser performance data available")
		return &ParserPerformance{}, nil
	} else if err != nil {
		logger.Error(" Failed to query parser performance",
			zap.Error(err),
			zap.String("query", query))
		return nil, fmt.Errorf("failed to query parser performance: %w", err)
	}

	logger.Info(" Parser performance data fetched",
		zap.Int("parsed_count", pp.ParsedCount),
		zap.Float64("success_rate", pp.SuccessRate))

	return &pp, nil
}

// GetRecentFailures fetches recent failures from the database view
func (dm *DashboardMonitor) GetRecentFailures(rc *eos_io.RuntimeContext, limit int) ([]RecentFailure, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Fetching recent failures data",
		zap.Int("limit", limit))

	query := `
		SELECT 
			id,
			state,
			error_message,
			failed_at,
			retry_count,
			agent_name,
			alert_level,
			rule_id
		FROM recent_failures
		ORDER BY failed_at DESC
		LIMIT $1
	`

	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	defer cancel()

	rows, err := dm.db.QueryContext(ctx, query, limit)
	if err != nil {
		logger.Error(" Failed to query recent failures",
			zap.Error(err),
			zap.String("query", query),
			zap.Int("limit", limit))
		return nil, fmt.Errorf("failed to query recent failures: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			logger.Warn(" Failed to close rows", zap.Error(closeErr))
		}
	}()

	var results []RecentFailure
	for rows.Next() {
		var rf RecentFailure
		var errorMessage sql.NullString
		var agentName sql.NullString
		var alertLevel sql.NullString
		var ruleID sql.NullString

		err := rows.Scan(
			&rf.ID,
			&rf.State,
			&errorMessage,
			&rf.FailedAt,
			&rf.RetryCount,
			&agentName,
			&alertLevel,
			&ruleID,
		)
		if err != nil {
			logger.Error(" Failed to scan recent failure row",
				zap.Error(err))
			return nil, fmt.Errorf("failed to scan recent failure row: %w", err)
		}

		// Handle nullable fields
		rf.ErrorMessage = errorMessage.String
		rf.AgentName = agentName.String
		rf.AlertLevel = alertLevel.String
		rf.RuleID = ruleID.String

		results = append(results, rf)
	}

	if err = rows.Err(); err != nil {
		logger.Error(" Error iterating recent failure rows",
			zap.Error(err))
		return nil, fmt.Errorf("error iterating recent failure rows: %w", err)
	}

	logger.Info(" Recent failures data fetched",
		zap.Int("record_count", len(results)))

	return results, nil
}

// GetDailySummary fetches daily operations summary
func (dm *DashboardMonitor) GetDailySummary(rc *eos_io.RuntimeContext, date time.Time) (*DailyOperationsSummary, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Fetching daily summary data",
		zap.String("date", date.Format("2006-01-02")))

	// For now, we'll create a basic summary by aggregating from alerts table
	// This would be replaced with the actual daily summary view when implemented
	query := `
		WITH daily_stats AS (
			SELECT 
				DATE(created_at) as date,
				COUNT(*) as total_alerts_processed,
				COUNT(CASE WHEN alert_state NOT IN ('failed') THEN 1 END) as total_alerts_successful,
				COUNT(CASE WHEN alert_state = 'failed' THEN 1 END) as total_alerts_failed,
				AVG(EXTRACT(EPOCH FROM (updated_at - created_at))) as avg_processing_time,
				EXTRACT(HOUR FROM created_at) as hour,
				COUNT(*) as hour_count
			FROM alerts 
			WHERE DATE(created_at) = $1
			GROUP BY DATE(created_at), EXTRACT(HOUR FROM created_at)
		),
		peak_hour AS (
			SELECT hour, hour_count
			FROM daily_stats
			ORDER BY hour_count DESC
			LIMIT 1
		)
		SELECT 
			ds.date,
			ds.total_alerts_processed,
			ds.total_alerts_successful,
			ds.total_alerts_failed,
			CASE 
				WHEN ds.total_alerts_processed > 0 
				THEN (ds.total_alerts_successful::float / ds.total_alerts_processed::float) * 100
				ELSE 0 
			END as success_rate,
			ds.avg_processing_time,
			ph.hour as peak_hour,
			ph.hour_count as peak_hour_alert_count
		FROM daily_stats ds
		CROSS JOIN peak_hour ph
		LIMIT 1
	`

	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	defer cancel()

	var ds DailyOperationsSummary
	var peakHour sql.NullInt64
	var peakHourCount sql.NullInt64

	err := dm.db.QueryRowContext(ctx, query, date.Format("2006-01-02")).Scan(
		&ds.Date,
		&ds.TotalAlertsProcessed,
		&ds.TotalAlertsSuccessful,
		&ds.TotalAlertsFailed,
		&ds.SuccessRate,
		&ds.AvgProcessingTime,
		&peakHour,
		&peakHourCount,
	)

	if err == sql.ErrNoRows {
		logger.Warn(" No daily summary data available for date",
			zap.String("date", date.Format("2006-01-02")))
		return &DailyOperationsSummary{
			Date:                  date,
			TotalAlertsProcessed:  0,
			TotalAlertsSuccessful: 0,
			TotalAlertsFailed:     0,
			SuccessRate:           0,
			AvgProcessingTime:     0,
			TopFailureReasons:     []string{},
			PeakHour:              0,
			PeakHourAlertCount:    0,
		}, nil
	} else if err != nil {
		logger.Error(" Failed to query daily summary",
			zap.Error(err),
			zap.String("query", query),
			zap.String("date", date.Format("2006-01-02")))
		return nil, fmt.Errorf("failed to query daily summary: %w", err)
	}

	// Handle nullable fields
	if peakHour.Valid {
		ds.PeakHour = int(peakHour.Int64)
	}
	if peakHourCount.Valid {
		ds.PeakHourAlertCount = int(peakHourCount.Int64)
	}

	// TODO: Implement top failure reasons query
	ds.TopFailureReasons = []string{}

	logger.Info(" Daily summary data fetched",
		zap.Int("total_processed", ds.TotalAlertsProcessed),
		zap.Float64("success_rate", ds.SuccessRate))

	return &ds, nil
}

// GetAllDashboardData fetches all dashboard data in one operation
func (dm *DashboardMonitor) GetAllDashboardData(rc *eos_io.RuntimeContext) (*DashboardData, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Fetching all dashboard data")

	start := time.Now()

	// Fetch all data concurrently
	type result struct {
		pipelineHealth    []PipelineHealth
		bottlenecks       []PipelineBottleneck
		parserPerformance *ParserPerformance
		recentFailures    []RecentFailure
		dailySummary      *DailyOperationsSummary
		err               error
	}

	resultChan := make(chan result, 1)

	go func() {
		var r result

		// Fetch pipeline health
		if r.pipelineHealth, r.err = dm.GetPipelineHealth(rc); r.err != nil {
			resultChan <- r
			return
		}

		// Fetch bottlenecks
		if r.bottlenecks, r.err = dm.GetPipelineBottlenecks(rc); r.err != nil {
			resultChan <- r
			return
		}

		// Fetch parser performance
		if r.parserPerformance, r.err = dm.GetParserPerformance(rc); r.err != nil {
			resultChan <- r
			return
		}

		// Fetch recent failures (limit to 20)
		if r.recentFailures, r.err = dm.GetRecentFailures(rc, 20); r.err != nil {
			resultChan <- r
			return
		}

		// Fetch daily summary for today
		if r.dailySummary, r.err = dm.GetDailySummary(rc, time.Now()); r.err != nil {
			resultChan <- r
			return
		}

		resultChan <- r
	}()

	// Wait for results with timeout
	select {
	case r := <-resultChan:
		if r.err != nil {
			logger.Error(" Failed to fetch dashboard data",
				zap.Error(r.err),
				zap.Duration("duration", time.Since(start)))
			return nil, r.err
		}

		dashboardData := &DashboardData{
			PipelineHealth:    r.pipelineHealth,
			Bottlenecks:       r.bottlenecks,
			ParserPerformance: r.parserPerformance,
			RecentFailures:    r.recentFailures,
			DailySummary:      r.dailySummary,
			LastUpdated:       time.Now(),
		}

		logger.Info(" All dashboard data fetched successfully",
			zap.Duration("total_duration", time.Since(start)),
			zap.Int("pipeline_health_records", len(dashboardData.PipelineHealth)),
			zap.Int("bottleneck_records", len(dashboardData.Bottlenecks)),
			zap.Int("recent_failure_records", len(dashboardData.RecentFailures)))

		return dashboardData, nil

	case <-time.After(30 * time.Second):
		logger.Error(" Timeout fetching dashboard data",
			zap.Duration("timeout", 30*time.Second))
		return nil, fmt.Errorf("timeout fetching dashboard data after 30 seconds")
	}
}

// RefreshData is a convenience method to refresh all dashboard data
func (dm *DashboardMonitor) RefreshData(rc *eos_io.RuntimeContext) (*DashboardData, error) {
	return dm.GetAllDashboardData(rc)
}

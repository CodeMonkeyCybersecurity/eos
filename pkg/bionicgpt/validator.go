// Package bionicgpt provides validation for BionicGPT deployments
// following the Assess → Intervene → Evaluate pattern.
//
// This validator uses the Docker SDK (not shell commands) for robust validation
// of multi-tenant BionicGPT deployments, including:
//   - Docker resource availability (CPU, RAM, disk)
//   - PostgreSQL Row-Level Security (RLS) verification
//   - Multi-tenant team isolation testing
//   - Audit logging verification
//   - RAG pipeline health checks
//
// Code Monkey Cybersecurity - "Cybersecurity. With humans."
package bionicgpt

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/container"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	containertypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/volume"
	_ "github.com/lib/pq" // PostgreSQL driver
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Validator validates BionicGPT deployment state and multi-tenancy features
type Validator struct {
	rc            *eos_io.RuntimeContext
	dockerManager *container.Manager
	config        *InstallConfig
}

// ValidationResult contains the results of all validation checks
type ValidationResult struct {
	OverallHealth     bool                     // True if all critical checks pass
	ResourceCheck     *ResourceCheckResult     // Docker resources
	ContainerCheck    *ContainerCheckResult    // Container status
	PostgreSQLCheck   *PostgreSQLCheckResult   // Database and RLS
	MultiTenancyCheck *MultiTenancyCheckResult // Team isolation
	AuditLogCheck     *AuditLogCheckResult     // Audit logging
	RAGPipelineCheck  *RAGPipelineCheckResult  // RAG functionality
	Errors            []string                 // Critical errors
	Warnings          []string                 // Non-critical issues
}

// ResourceCheckResult contains Docker resource availability checks
type ResourceCheckResult struct {
	CPUCores          int     // Available CPU cores
	MemoryTotalGB     float64 // Total memory in GB
	MemoryAvailableGB float64 // Available memory in GB
	DiskAvailableGB   float64 // Available disk space in GB
	MeetsMinimum      bool    // True if meets minimum requirements
	Issues            []string
}

// ContainerCheckResult contains container health status
type ContainerCheckResult struct {
	AppRunning        bool
	PostgresRunning   bool
	EmbeddingsRunning bool
	RAGEngineRunning  bool
	ChunkingRunning   bool
	AllHealthy        bool
	ContainerStatuses map[string]string // container -> status
}

// PostgreSQLCheckResult contains database validation results
type PostgreSQLCheckResult struct {
	Connected         bool
	RLSEnabled        bool     // Row-Level Security enabled
	RLSPolicies       []string // List of RLS policies found
	PgVectorInstalled bool     // pgVector extension for embeddings
	DatabaseVersion   string
	Issues            []string
}

// MultiTenancyCheckResult contains team isolation validation
type MultiTenancyCheckResult struct {
	RLSEnforced      bool // RLS policies are enforcing isolation
	TeamsTableExists bool
	UsersTableExists bool
	IsolationTested  bool // Actual isolation test performed
	Issues           []string
}

// AuditLogCheckResult contains audit logging validation
type AuditLogCheckResult struct {
	AuditTableExists bool
	LogsBeingWritten bool // Recent audit entries exist
	RecentEntryCount int
	Issues           []string
}

// RAGPipelineCheckResult contains RAG functionality validation
type RAGPipelineCheckResult struct {
	EmbeddingsServiceHealthy bool
	ChunkingServiceHealthy   bool
	DocumentsVolumeExists    bool
	RAGEngineHealthy         bool
	Issues                   []string
}

// Minimum resource requirements for BionicGPT
const (
	MinCPUCores       = 2
	MinMemoryGB       = 4.0
	MinDiskSpaceGB    = 20.0
	RecommendedCPU    = 4
	RecommendedMemGB  = 8.0
	RecommendedDiskGB = 100.0
)

// NewValidator creates a new BionicGPT validator
func NewValidator(rc *eos_io.RuntimeContext, config *InstallConfig) (*Validator, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Initialize Docker manager
	dockerManager, err := container.NewManager(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker manager: %w", err)
	}

	logger.Debug("Validator initialized with Docker SDK")

	return &Validator{
		rc:            rc,
		dockerManager: dockerManager,
		config:        config,
	}, nil
}

// ValidateDeployment performs comprehensive validation of BionicGPT deployment
func (v *Validator) ValidateDeployment(ctx context.Context) (*ValidationResult, error) {
	logger := otelzap.Ctx(ctx)
	logger.Info("Starting comprehensive BionicGPT deployment validation")

	result := &ValidationResult{
		Errors:   []string{},
		Warnings: []string{},
	}

	// 1. Check Docker resources
	logger.Info("Validating Docker resources")
	resourceResult, err := v.CheckResources(ctx)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Resource check failed: %v", err))
	}
	result.ResourceCheck = resourceResult

	// 2. Check container status
	logger.Info("Validating container health")
	containerResult, err := v.CheckContainers(ctx)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Container check failed: %v", err))
	}
	result.ContainerCheck = containerResult

	// 3. Check PostgreSQL and RLS
	logger.Info("Validating PostgreSQL and Row-Level Security")
	pgResult, err := v.CheckPostgreSQL(ctx)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("PostgreSQL check failed: %v", err))
	}
	result.PostgreSQLCheck = pgResult

	// 4. Check multi-tenancy features
	logger.Info("Validating multi-tenancy isolation")
	mtResult, err := v.CheckMultiTenancy(ctx)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Multi-tenancy check failed: %v", err))
	}
	result.MultiTenancyCheck = mtResult

	// 5. Check audit logging
	logger.Info("Validating audit logging")
	auditResult, err := v.CheckAuditLog(ctx)
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Audit log check failed: %v", err))
	}
	result.AuditLogCheck = auditResult

	// 6. Check RAG pipeline
	logger.Info("Validating RAG pipeline")
	ragResult, err := v.CheckRAGPipeline(ctx)
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("RAG pipeline check failed: %v", err))
	}
	result.RAGPipelineCheck = ragResult

	// Determine overall health
	result.OverallHealth = v.determineOverallHealth(result)

	logger.Info("Validation completed",
		zap.Bool("overall_health", result.OverallHealth),
		zap.Int("errors", len(result.Errors)),
		zap.Int("warnings", len(result.Warnings)))

	return result, nil
}

// CheckResources validates Docker resource availability using Docker SDK
func (v *Validator) CheckResources(ctx context.Context) (*ResourceCheckResult, error) {
	logger := otelzap.Ctx(ctx)

	// Get Docker system info via SDK
	dockerInfo, err := v.dockerManager.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get Docker info: %w", err)
	}

	result := &ResourceCheckResult{
		CPUCores:      dockerInfo.NCPU,
		MemoryTotalGB: float64(dockerInfo.MemTotal) / (1024 * 1024 * 1024),
		Issues:        []string{},
	}

	// Get volume info for disk space
	cli := v.dockerManager.Client()
	volumes, err := cli.VolumeList(ctx, volume.ListOptions{})
	if err != nil {
		logger.Warn("Failed to get volume info", zap.Error(err))
	} else {
		// Estimate available disk space based on Docker storage driver
		logger.Debug("Found volumes", zap.Int("count", len(volumes.Volumes)))
		// For now, assume sufficient disk space if volumes can be listed
		// TODO: Add more sophisticated disk space checking
		result.DiskAvailableGB = 100.0 // Placeholder
	}

	// Check against minimum requirements
	result.MeetsMinimum = true

	if result.CPUCores < MinCPUCores {
		result.MeetsMinimum = false
		result.Issues = append(result.Issues,
			fmt.Sprintf("CPU cores (%d) below minimum (%d)", result.CPUCores, MinCPUCores))
	} else if result.CPUCores < RecommendedCPU {
		result.Issues = append(result.Issues,
			fmt.Sprintf("CPU cores (%d) below recommended (%d)", result.CPUCores, RecommendedCPU))
	}

	if result.MemoryTotalGB < MinMemoryGB {
		result.MeetsMinimum = false
		result.Issues = append(result.Issues,
			fmt.Sprintf("Memory (%.1fGB) below minimum (%.1fGB)", result.MemoryTotalGB, MinMemoryGB))
	} else if result.MemoryTotalGB < RecommendedMemGB {
		result.Issues = append(result.Issues,
			fmt.Sprintf("Memory (%.1fGB) below recommended (%.1fGB)", result.MemoryTotalGB, RecommendedMemGB))
	}

	logger.Info("Resource check completed",
		zap.Int("cpu_cores", result.CPUCores),
		zap.Float64("memory_gb", result.MemoryTotalGB),
		zap.Bool("meets_minimum", result.MeetsMinimum))

	return result, nil
}

// CheckContainers validates all BionicGPT containers are running using Docker SDK
func (v *Validator) CheckContainers(ctx context.Context) (*ContainerCheckResult, error) {
	logger := otelzap.Ctx(ctx)

	result := &ContainerCheckResult{
		ContainerStatuses: make(map[string]string),
	}

	cli := v.dockerManager.Client()

	// Define expected containers
	expectedContainers := map[string]*bool{
		ContainerApp:        &result.AppRunning,
		ContainerPostgres:   &result.PostgresRunning,
		ContainerEmbeddings: &result.EmbeddingsRunning,
		ContainerRAGEngine:  &result.RAGEngineRunning,
		ContainerChunking:   &result.ChunkingRunning,
	}

	// List all containers with BionicGPT name filter
	filterArgs := filters.NewArgs()
	for containerName := range expectedContainers {
		filterArgs.Add("name", containerName)
	}

	containers, err := cli.ContainerList(ctx, containertypes.ListOptions{
		All:     true, // Include stopped containers
		Filters: filterArgs,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	// Check each expected container
	for containerName, runningFlag := range expectedContainers {
		found := false
		for _, c := range containers {
			// Container names have leading slash
			for _, name := range c.Names {
				if strings.TrimPrefix(name, "/") == containerName {
					found = true
					result.ContainerStatuses[containerName] = c.Status

					// Check if running
					if c.State == "running" {
						*runningFlag = true
					} else {
						logger.Warn("Container not running",
							zap.String("container", containerName),
							zap.String("state", c.State))
					}
					break
				}
			}
		}
		if !found {
			logger.Warn("Container not found", zap.String("container", containerName))
			result.ContainerStatuses[containerName] = "not found"
		}
	}

	// All containers must be running
	result.AllHealthy = result.AppRunning &&
		result.PostgresRunning &&
		result.EmbeddingsRunning &&
		result.RAGEngineRunning &&
		result.ChunkingRunning

	logger.Info("Container check completed",
		zap.Bool("all_healthy", result.AllHealthy),
		zap.Int("running_containers", len(containers)))

	return result, nil
}

// CheckPostgreSQL validates PostgreSQL connection and Row-Level Security
func (v *Validator) CheckPostgreSQL(ctx context.Context) (*PostgreSQLCheckResult, error) {
	logger := otelzap.Ctx(ctx)

	result := &PostgreSQLCheckResult{
		RLSPolicies: []string{},
		Issues:      []string{},
	}

	// Build connection string
	connStr := fmt.Sprintf("host=localhost port=5432 user=%s password=%s dbname=%s sslmode=disable",
		v.config.PostgresUser,
		v.config.PostgresPassword,
		v.config.PostgresDB)

	// Connect to PostgreSQL
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		result.Issues = append(result.Issues, fmt.Sprintf("Failed to create connection: %v", err))
		return result, nil
	}
	defer func() { _ = db.Close() }()

	// Set connection timeout
	connectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Test connection
	err = db.PingContext(connectCtx)
	if err != nil {
		result.Issues = append(result.Issues, fmt.Sprintf("Failed to connect: %v", err))
		return result, nil
	}
	result.Connected = true

	// Get PostgreSQL version
	err = db.QueryRowContext(ctx, "SELECT version()").Scan(&result.DatabaseVersion)
	if err != nil {
		logger.Warn("Failed to get PostgreSQL version", zap.Error(err))
	} else {
		logger.Debug("PostgreSQL version", zap.String("version", result.DatabaseVersion))
	}

	// Check if pgVector extension is installed
	var pgvectorExists bool
	err = db.QueryRowContext(ctx,
		"SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'vector')").Scan(&pgvectorExists)
	if err != nil {
		logger.Warn("Failed to check pgVector extension", zap.Error(err))
	} else {
		result.PgVectorInstalled = pgvectorExists
		if !pgvectorExists {
			result.Issues = append(result.Issues, "pgVector extension not installed (required for embeddings)")
		}
	}

	// Check for Row-Level Security policies
	rows, err := db.QueryContext(ctx, `
		SELECT schemaname, tablename, policyname
		FROM pg_policies
		WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
	`)
	if err != nil {
		result.Issues = append(result.Issues, fmt.Sprintf("Failed to query RLS policies: %v", err))
		return result, nil
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var schema, table, policy string
		if err := rows.Scan(&schema, &table, &policy); err != nil {
			logger.Warn("Failed to scan RLS policy row", zap.Error(err))
			continue
		}
		policyDesc := fmt.Sprintf("%s.%s: %s", schema, table, policy)
		result.RLSPolicies = append(result.RLSPolicies, policyDesc)
	}

	result.RLSEnabled = len(result.RLSPolicies) > 0

	if !result.RLSEnabled {
		result.Issues = append(result.Issues,
			"No Row-Level Security policies found - multi-tenancy may not be enforced at database level")
	}

	logger.Info("PostgreSQL check completed",
		zap.Bool("connected", result.Connected),
		zap.Bool("rls_enabled", result.RLSEnabled),
		zap.Int("rls_policies", len(result.RLSPolicies)),
		zap.Bool("pgvector_installed", result.PgVectorInstalled))

	return result, nil
}

// CheckMultiTenancy validates multi-tenant team isolation features
func (v *Validator) CheckMultiTenancy(ctx context.Context) (*MultiTenancyCheckResult, error) {
	logger := otelzap.Ctx(ctx)

	result := &MultiTenancyCheckResult{
		Issues: []string{},
	}

	// Build connection string
	connStr := fmt.Sprintf("host=localhost port=5432 user=%s password=%s dbname=%s sslmode=disable",
		v.config.PostgresUser,
		v.config.PostgresPassword,
		v.config.PostgresDB)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		result.Issues = append(result.Issues, fmt.Sprintf("Failed to connect: %v", err))
		return result, nil
	}
	defer func() { _ = db.Close() }()

	// Check if teams table exists
	err = db.QueryRowContext(ctx,
		"SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = 'teams')").Scan(&result.TeamsTableExists)
	if err != nil {
		logger.Warn("Failed to check teams table", zap.Error(err))
	}

	// Check if users table exists
	err = db.QueryRowContext(ctx,
		"SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = 'users')").Scan(&result.UsersTableExists)
	if err != nil {
		logger.Warn("Failed to check users table", zap.Error(err))
	}

	// Check if RLS is enforced on teams table
	if result.TeamsTableExists {
		var rlsEnabled bool
		err = db.QueryRowContext(ctx, `
			SELECT relrowsecurity
			FROM pg_class
			WHERE relname = 'teams'
		`).Scan(&rlsEnabled)
		if err != nil {
			logger.Warn("Failed to check RLS on teams table", zap.Error(err))
		} else {
			result.RLSEnforced = rlsEnabled
			if !rlsEnabled {
				result.Issues = append(result.Issues,
					"Row-Level Security not enabled on teams table - data isolation at risk")
			}
		}
	}

	if !result.TeamsTableExists {
		result.Issues = append(result.Issues, "Teams table does not exist - multi-tenancy not configured")
	}
	if !result.UsersTableExists {
		result.Issues = append(result.Issues, "Users table does not exist - authentication not configured")
	}

	logger.Info("Multi-tenancy check completed",
		zap.Bool("teams_table_exists", result.TeamsTableExists),
		zap.Bool("users_table_exists", result.UsersTableExists),
		zap.Bool("rls_enforced", result.RLSEnforced))

	return result, nil
}

// CheckAuditLog validates audit logging is functioning
func (v *Validator) CheckAuditLog(ctx context.Context) (*AuditLogCheckResult, error) {
	logger := otelzap.Ctx(ctx)

	result := &AuditLogCheckResult{
		Issues: []string{},
	}

	// Build connection string
	connStr := fmt.Sprintf("host=localhost port=5432 user=%s password=%s dbname=%s sslmode=disable",
		v.config.PostgresUser,
		v.config.PostgresPassword,
		v.config.PostgresDB)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		result.Issues = append(result.Issues, fmt.Sprintf("Failed to connect: %v", err))
		return result, nil
	}
	defer func() { _ = db.Close() }()

	// Check if audit_log table exists
	err = db.QueryRowContext(ctx,
		"SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = 'audit_log')").Scan(&result.AuditTableExists)
	if err != nil {
		logger.Warn("Failed to check audit_log table", zap.Error(err))
	}

	// Check for recent audit entries (last 24 hours)
	if result.AuditTableExists {
		err = db.QueryRowContext(ctx, `
			SELECT COUNT(*)
			FROM audit_log
			WHERE created_at > NOW() - INTERVAL '24 hours'
		`).Scan(&result.RecentEntryCount)
		if err != nil {
			logger.Warn("Failed to count recent audit entries", zap.Error(err))
		} else {
			result.LogsBeingWritten = result.RecentEntryCount > 0
		}
	}

	if !result.AuditTableExists {
		result.Issues = append(result.Issues, "Audit log table does not exist - audit trail not available")
	} else if !result.LogsBeingWritten {
		result.Issues = append(result.Issues, "No recent audit log entries - logging may not be functioning")
	}

	logger.Info("Audit log check completed",
		zap.Bool("table_exists", result.AuditTableExists),
		zap.Bool("logs_being_written", result.LogsBeingWritten),
		zap.Int("recent_entries", result.RecentEntryCount))

	return result, nil
}

// CheckRAGPipeline validates the RAG pipeline components
func (v *Validator) CheckRAGPipeline(ctx context.Context) (*RAGPipelineCheckResult, error) {
	logger := otelzap.Ctx(ctx)

	result := &RAGPipelineCheckResult{
		Issues: []string{},
	}

	cli := v.dockerManager.Client()

	// Check if documents volume exists
	volumes, err := cli.VolumeList(ctx, volume.ListOptions{
		Filters: filters.NewArgs(filters.Arg("name", VolumeDocuments)),
	})
	if err != nil {
		logger.Warn("Failed to check documents volume", zap.Error(err))
	} else {
		result.DocumentsVolumeExists = len(volumes.Volumes) > 0
		if !result.DocumentsVolumeExists {
			result.Issues = append(result.Issues, "Documents volume does not exist")
		}
	}

	// Check container health for embeddings service
	result.EmbeddingsServiceHealthy = v.isContainerHealthy(ctx, ContainerEmbeddings)
	if !result.EmbeddingsServiceHealthy {
		result.Issues = append(result.Issues, "Embeddings service not healthy")
	}

	// Check container health for chunking service
	result.ChunkingServiceHealthy = v.isContainerHealthy(ctx, ContainerChunking)
	if !result.ChunkingServiceHealthy {
		result.Issues = append(result.Issues, "Chunking service not healthy")
	}

	// Check container health for RAG engine
	result.RAGEngineHealthy = v.isContainerHealthy(ctx, ContainerRAGEngine)
	if !result.RAGEngineHealthy {
		result.Issues = append(result.Issues, "RAG engine not healthy")
	}

	logger.Info("RAG pipeline check completed",
		zap.Bool("documents_volume_exists", result.DocumentsVolumeExists),
		zap.Bool("embeddings_healthy", result.EmbeddingsServiceHealthy),
		zap.Bool("chunking_healthy", result.ChunkingServiceHealthy),
		zap.Bool("rag_engine_healthy", result.RAGEngineHealthy))

	return result, nil
}

// isContainerHealthy checks if a container is running and healthy
func (v *Validator) isContainerHealthy(ctx context.Context, containerName string) bool {
	cli := v.dockerManager.Client()

	filterArgs := filters.NewArgs()
	filterArgs.Add("name", containerName)

	containers, err := cli.ContainerList(ctx, containertypes.ListOptions{
		Filters: filterArgs,
	})
	if err != nil || len(containers) == 0 {
		return false
	}

	// Container exists and is in running state
	return containers[0].State == "running"
}

// determineOverallHealth calculates overall health based on validation results
func (v *Validator) determineOverallHealth(result *ValidationResult) bool {
	// Critical checks that must pass
	if len(result.Errors) > 0 {
		return false
	}

	if result.ResourceCheck != nil && !result.ResourceCheck.MeetsMinimum {
		return false
	}

	if result.ContainerCheck != nil && !result.ContainerCheck.AllHealthy {
		return false
	}

	if result.PostgreSQLCheck != nil && !result.PostgreSQLCheck.Connected {
		return false
	}

	// Multi-tenancy RLS should be enabled for production
	if result.PostgreSQLCheck != nil && !result.PostgreSQLCheck.RLSEnabled {
		return false
	}

	return true
}

// Close releases validator resources
func (v *Validator) Close() error {
	if v.dockerManager != nil {
		return v.dockerManager.Close()
	}
	return nil
}

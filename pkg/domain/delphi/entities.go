// Package delphi defines domain entities for security monitoring and tenant management
package delphi

import (
	"time"
)

// Core entity types for Delphi security monitoring platform

// Tenant represents a security monitoring tenant
type Tenant struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	DisplayName  string            `json:"display_name,omitempty"`
	Description  string            `json:"description,omitempty"`
	Status       TenantStatus      `json:"status"`
	Environment  string            `json:"environment,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
	Labels       map[string]string `json:"labels,omitempty"`
	Configuration *TenantConfiguration `json:"configuration,omitempty"`
	Resources    *TenantResources  `json:"resources,omitempty"`
	Security     *TenantSecurity   `json:"security,omitempty"`
}

// TenantSpec defines tenant creation/update specification
type TenantSpec struct {
	Name         string            `json:"name"`
	DisplayName  string            `json:"display_name,omitempty"`
	Description  string            `json:"description,omitempty"`
	Environment  string            `json:"environment,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	Configuration *TenantConfiguration `json:"configuration,omitempty"`
	Resources    *TenantResources  `json:"resources,omitempty"`
	Security     *TenantSecurity   `json:"security,omitempty"`
}

// TenantConfiguration holds tenant-specific configuration
type TenantConfiguration struct {
	RetentionDays     int                    `json:"retention_days"`
	AlertingEnabled   bool                   `json:"alerting_enabled"`
	ComplianceFrameworks []string            `json:"compliance_frameworks,omitempty"`
	CustomSettings    map[string]interface{} `json:"custom_settings,omitempty"`
	WazuhConfig       *WazuhConfiguration    `json:"wazuh_config,omitempty"`
	OpenSearchConfig  *OpenSearchConfig      `json:"opensearch_config,omitempty"`
	LDAPConfig        *LDAPConfig            `json:"ldap_config,omitempty"`
}

// TenantResources defines resource allocation for tenant
type TenantResources struct {
	StorageQuotaGB    int     `json:"storage_quota_gb"`
	CPULimit          float64 `json:"cpu_limit"`
	MemoryLimitGB     int     `json:"memory_limit_gb"`
	MaxUsers          int     `json:"max_users"`
	MaxAgents         int     `json:"max_agents"`
	MaxIndices        int     `json:"max_indices"`
}

// TenantSecurity defines security settings for tenant
type TenantSecurity struct {
	EncryptionEnabled bool               `json:"encryption_enabled"`
	MFARequired      bool               `json:"mfa_required"`
	IPWhitelist      []string           `json:"ip_whitelist,omitempty"`
	AccessPolicies   []*AccessControl   `json:"access_policies,omitempty"`
	AuditLevel       string             `json:"audit_level"`
	ComplianceMode   bool               `json:"compliance_mode"`
}

// TenantProvisionResult holds the result of tenant provisioning
type TenantProvisionResult struct {
	TenantID     string    `json:"tenant_id"`
	ProvisionID  string    `json:"provision_id"`
	Status       string    `json:"status"`
	Message      string    `json:"message,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	EstimatedCompletion *time.Time `json:"estimated_completion,omitempty"`
}

// ProvisioningStatus tracks the status of tenant provisioning
type ProvisioningStatus struct {
	ProvisionID  string                 `json:"provision_id"`
	TenantID     string                 `json:"tenant_id"`
	Status       string                 `json:"status"`
	Progress     int                    `json:"progress"` // 0-100
	CurrentStep  string                 `json:"current_step"`
	Steps        []*ProvisioningStep    `json:"steps"`
	StartedAt    time.Time              `json:"started_at"`
	CompletedAt  *time.Time             `json:"completed_at,omitempty"`
	Error        string                 `json:"error,omitempty"`
}

// ProvisioningStep represents a step in the provisioning process
type ProvisioningStep struct {
	Name        string     `json:"name"`
	Status      string     `json:"status"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Error       string     `json:"error,omitempty"`
}

// User represents a user in the Delphi platform
type User struct {
	ID          string      `json:"id"`
	Username    string      `json:"username"`
	Email       string      `json:"email"`
	FirstName   string      `json:"first_name,omitempty"`
	LastName    string      `json:"last_name,omitempty"`
	Status      UserStatus  `json:"status"`
	Roles       []string    `json:"roles,omitempty"`
	Department  string      `json:"department,omitempty"`
	TenantIDs   []string    `json:"tenant_ids,omitempty"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
	LastLogin   *time.Time  `json:"last_login,omitempty"`
	MFAEnabled  bool        `json:"mfa_enabled"`
	Preferences map[string]interface{} `json:"preferences,omitempty"`
}

// UserSpec defines user creation/update specification
type UserSpec struct {
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	FirstName   string   `json:"first_name,omitempty"`
	LastName    string   `json:"last_name,omitempty"`
	Password    string   `json:"password,omitempty"`
	Roles       []string `json:"roles,omitempty"`
	Department  string   `json:"department,omitempty"`
	TenantIDs   []string `json:"tenant_ids,omitempty"`
	MFAEnabled  bool     `json:"mfa_enabled"`
	Preferences map[string]interface{} `json:"preferences,omitempty"`
}

// UserCredentials represents user login credentials
type UserCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
	MFAToken string `json:"mfa_token,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`
}

// UserSession represents an active user session
type UserSession struct {
	ID         string    `json:"id"`
	UserID     string    `json:"user_id"`
	TenantID   string    `json:"tenant_id,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastAccess time.Time `json:"last_access"`
	IPAddress  string    `json:"ip_address,omitempty"`
	UserAgent  string    `json:"user_agent,omitempty"`
	Active     bool      `json:"active"`
}

// Alert represents a security alert
type Alert struct {
	ID          string        `json:"id"`
	TenantID    string        `json:"tenant_id"`
	Title       string        `json:"title"`
	Description string        `json:"description"`
	Severity    AlertSeverity `json:"severity"`
	Status      AlertStatus   `json:"status"`
	Type        AlertType     `json:"type"`
	Source      string        `json:"source"`
	Tags        []string      `json:"tags,omitempty"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
	AcknowledgedBy string     `json:"acknowledged_by,omitempty"`
	ResolvedAt  *time.Time    `json:"resolved_at,omitempty"`
	ResolvedBy  string        `json:"resolved_by,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// AlertSpec defines alert creation specification
type AlertSpec struct {
	TenantID    string        `json:"tenant_id"`
	Title       string        `json:"title"`
	Description string        `json:"description"`
	Severity    AlertSeverity `json:"severity"`
	Type        AlertType     `json:"type"`
	Source      string        `json:"source"`
	Tags        []string      `json:"tags,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// AlertUpdate represents an alert update
type AlertUpdate struct {
	Title       *string       `json:"title,omitempty"`
	Description *string       `json:"description,omitempty"`
	Severity    *AlertSeverity `json:"severity,omitempty"`
	Status      *AlertStatus  `json:"status,omitempty"`
	Tags        []string      `json:"tags,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// AlertResolution represents alert resolution details
type AlertResolution struct {
	Resolution string    `json:"resolution"`
	ResolvedBy string    `json:"resolved_by"`
	ResolvedAt time.Time `json:"resolved_at"`
	Notes      string    `json:"notes,omitempty"`
}

// SecurityAlert represents a security-specific alert with additional context
type SecurityAlert struct {
	Alert
	RuleID         string                 `json:"rule_id,omitempty"`
	IncidentID     string                 `json:"incident_id,omitempty"`
	AffectedAssets []string               `json:"affected_assets,omitempty"`
	ThreatLevel    string                 `json:"threat_level,omitempty"`
	Indicators     []*ThreatIndicator     `json:"indicators,omitempty"`
	Evidence       map[string]interface{} `json:"evidence,omitempty"`
}

// SecurityDashboard represents a security monitoring dashboard
type SecurityDashboard struct {
	TenantID         string                 `json:"tenant_id"`
	GeneratedAt      time.Time              `json:"generated_at"`
	AlertSummary     *AlertSummary          `json:"alert_summary"`
	ThreatSummary    *ThreatSummary         `json:"threat_summary"`
	ComplianceStatus *ComplianceStatus      `json:"compliance_status"`
	SystemHealth     *SystemHealth          `json:"system_health"`
	RecentIncidents  []*SecurityIncident    `json:"recent_incidents,omitempty"`
	TopThreats       []*ThreatIndicator     `json:"top_threats,omitempty"`
	Metrics          *SecurityMetrics       `json:"metrics,omitempty"`
}

// AlertSummary provides alert statistics
type AlertSummary struct {
	Total         int                       `json:"total"`
	BySeverity    map[AlertSeverity]int     `json:"by_severity"`
	ByStatus      map[AlertStatus]int       `json:"by_status"`
	ByType        map[AlertType]int         `json:"by_type"`
	Recent24Hours int                       `json:"recent_24_hours"`
	Trending      map[string]interface{}    `json:"trending,omitempty"`
}

// ThreatSummary provides threat intelligence summary
type ThreatSummary struct {
	ActiveThreats     int                    `json:"active_threats"`
	BlockedThreats    int                    `json:"blocked_threats"`
	NewThreats24h     int                    `json:"new_threats_24h"`
	ThreatsByType     map[string]int         `json:"threats_by_type"`
	ThreatSources     map[string]int         `json:"threat_sources"`
	HighRiskAssets    []string               `json:"high_risk_assets,omitempty"`
}

// AlertStatistics provides detailed alert analytics
type AlertStatistics struct {
	TenantID      string                    `json:"tenant_id"`
	TimeRange     *TimeRange                `json:"time_range"`
	TotalAlerts   int                       `json:"total_alerts"`
	BySeverity    map[AlertSeverity]int     `json:"by_severity"`
	ByStatus      map[AlertStatus]int       `json:"by_status"`
	ByType        map[AlertType]int         `json:"by_type"`
	ByHour        map[int]int               `json:"by_hour"`
	ByDay         map[string]int            `json:"by_day"`
	MeanTimeToAck time.Duration             `json:"mean_time_to_ack"`
	MeanTimeToResolve time.Duration         `json:"mean_time_to_resolve"`
	TopSources    map[string]int            `json:"top_sources"`
}

// SecurityMetrics represents security monitoring metrics
type SecurityMetrics struct {
	TenantID        string     `json:"tenant_id"`
	CollectedAt     time.Time  `json:"collected_at"`
	TimeRange       *TimeRange `json:"time_range"`
	EventsProcessed int64      `json:"events_processed"`
	AlertsGenerated int        `json:"alerts_generated"`
	IncidentsCreated int       `json:"incidents_created"`
	ThreatsDetected int        `json:"threats_detected"`
	ThreatsBlocked  int        `json:"threats_blocked"`
	SystemUptime    float64    `json:"system_uptime"`
	ProcessingLatency time.Duration `json:"processing_latency"`
	IndexSize      int64      `json:"index_size_bytes"`
	StorageUsed    int64      `json:"storage_used_bytes"`
}

// ThreatIntelligence represents threat intelligence data
type ThreatIntelligence struct {
	TenantID      string             `json:"tenant_id"`
	UpdatedAt     time.Time          `json:"updated_at"`
	Indicators    []*ThreatIndicator `json:"indicators"`
	FeedSources   []string           `json:"feed_sources"`
	TotalIndicators int              `json:"total_indicators"`
	ActiveThreats int                `json:"active_threats"`
	RecentUpdates int                `json:"recent_updates"`
}

// ThreatIndicator represents a threat indicator
type ThreatIndicator struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"` // ip, domain, hash, url, etc.
	Value       string    `json:"value"`
	Confidence  float64   `json:"confidence"` // 0.0 to 1.0
	Severity    string    `json:"severity"`
	Category    string    `json:"category"`
	Source      string    `json:"source"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Tags        []string  `json:"tags,omitempty"`
	Description string    `json:"description,omitempty"`
	Active      bool      `json:"active"`
}

// ThreatData represents raw threat data for analysis
type ThreatData struct {
	SourceIP      string                 `json:"source_ip,omitempty"`
	DestinationIP string                 `json:"destination_ip,omitempty"`
	UserAgent     string                 `json:"user_agent,omitempty"`
	RequestURL    string                 `json:"request_url,omitempty"`
	Payload       string                 `json:"payload,omitempty"`
	Timestamp     time.Time              `json:"timestamp"`
	EventType     string                 `json:"event_type"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// ThreatAnalysis represents the result of threat analysis
type ThreatAnalysis struct {
	ID              string             `json:"id"`
	ThreatData      *ThreatData        `json:"threat_data"`
	RiskScore       float64            `json:"risk_score"` // 0.0 to 10.0
	ThreatLevel     string             `json:"threat_level"`
	Category        string             `json:"category"`
	MatchedRules    []string           `json:"matched_rules,omitempty"`
	Indicators      []*ThreatIndicator `json:"indicators,omitempty"`
	Recommendations []string           `json:"recommendations,omitempty"`
	AnalyzedAt      time.Time          `json:"analyzed_at"`
	AnalysisTime    time.Duration      `json:"analysis_time"`
}

// SecurityIncident represents a security incident
type SecurityIncident struct {
	ID            string           `json:"id"`
	TenantID      string           `json:"tenant_id"`
	Title         string           `json:"title"`
	Description   string           `json:"description"`
	Severity      IncidentSeverity `json:"severity"`
	Status        IncidentStatus   `json:"status"`
	Type          IncidentType     `json:"type"`
	AssignedTo    string           `json:"assigned_to,omitempty"`
	CreatedBy     string           `json:"created_by"`
	CreatedAt     time.Time        `json:"created_at"`
	UpdatedAt     time.Time        `json:"updated_at"`
	ResolvedAt    *time.Time       `json:"resolved_at,omitempty"`
	Priority      string           `json:"priority"`
	Tags          []string         `json:"tags,omitempty"`
	RelatedAlerts []string         `json:"related_alerts,omitempty"`
	Evidence      []IncidentEvidence `json:"evidence,omitempty"`
	Timeline      []IncidentEvent  `json:"timeline,omitempty"`
	Resolution    string           `json:"resolution,omitempty"`
}

// IncidentSpec defines incident creation specification
type IncidentSpec struct {
	TenantID      string           `json:"tenant_id"`
	Title         string           `json:"title"`
	Description   string           `json:"description"`
	Severity      IncidentSeverity `json:"severity"`
	Type          IncidentType     `json:"type"`
	AssignedTo    string           `json:"assigned_to,omitempty"`
	Priority      string           `json:"priority"`
	Tags          []string         `json:"tags,omitempty"`
	RelatedAlerts []string         `json:"related_alerts,omitempty"`
}

// IncidentUpdate represents an incident update
type IncidentUpdate struct {
	Title       *string           `json:"title,omitempty"`
	Description *string           `json:"description,omitempty"`
	Severity    *IncidentSeverity `json:"severity,omitempty"`
	Status      *IncidentStatus   `json:"status,omitempty"`
	AssignedTo  *string           `json:"assigned_to,omitempty"`
	Priority    *string           `json:"priority,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Resolution  *string           `json:"resolution,omitempty"`
}

// IncidentEvidence represents evidence related to an incident
type IncidentEvidence struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Source      string                 `json:"source"`
	Description string                 `json:"description"`
	Data        map[string]interface{} `json:"data"`
	CollectedAt time.Time              `json:"collected_at"`
	CollectedBy string                 `json:"collected_by"`
}

// IncidentEvent represents an event in the incident timeline
type IncidentEvent struct {
	ID          string    `json:"id"`
	EventType   string    `json:"event_type"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
	UserID      string    `json:"user_id,omitempty"`
	Data        map[string]interface{} `json:"data,omitempty"`
}

// Wazuh-related entities

// WazuhCredentials represents Wazuh authentication credentials
type WazuhCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
	BaseURL  string `json:"base_url"`
}

// WazuhConfiguration represents Wazuh system configuration
type WazuhConfiguration struct {
	ManagerHost    string            `json:"manager_host"`
	ManagerPort    int               `json:"manager_port"`
	APIPort        int               `json:"api_port"`
	ClusterEnabled bool              `json:"cluster_enabled"`
	ClusterNodes   []string          `json:"cluster_nodes,omitempty"`
	AuthMethod     string            `json:"auth_method"`
	TLSEnabled     bool              `json:"tls_enabled"`
	Settings       map[string]interface{} `json:"settings,omitempty"`
}

// Agent represents a Wazuh agent
type Agent struct {
	ID           string      `json:"id"`
	Name         string      `json:"name"`
	IP           string      `json:"ip"`
	Status       AgentStatus `json:"status"`
	OS           string      `json:"os,omitempty"`
	Version      string      `json:"version,omitempty"`
	Groups       []string    `json:"groups,omitempty"`
	LastKeepAlive *time.Time `json:"last_keep_alive,omitempty"`
	RegisteredAt time.Time   `json:"registered_at"`
	ConfigHash   string      `json:"config_hash,omitempty"`
}

// AgentSpec defines agent registration specification
type AgentSpec struct {
	Name   string   `json:"name"`
	IP     string   `json:"ip"`
	Groups []string `json:"groups,omitempty"`
	OS     string   `json:"os,omitempty"`
}

// AgentConfig represents agent configuration
type AgentConfig struct {
	LogLevel    string                 `json:"log_level"`
	Modules     []string               `json:"modules"`
	Settings    map[string]interface{} `json:"settings"`
	Rules       []string               `json:"rules,omitempty"`
	Policies    []string               `json:"policies,omitempty"`
}

// AgentConfiguration represents complete agent configuration
type AgentConfiguration struct {
	AgentID     string                 `json:"agent_id"`
	Config      *AgentConfig           `json:"config"`
	Version     string                 `json:"version"`
	UpdatedAt   time.Time              `json:"updated_at"`
	AppliedAt   *time.Time             `json:"applied_at,omitempty"`
	Status      string                 `json:"status"`
}

// Index represents a data index
type Index struct {
	Name       string      `json:"name"`
	Status     IndexStatus `json:"status"`
	Health     string      `json:"health"`
	DocsCount  int64       `json:"docs_count"`
	StoreSize  int64       `json:"store_size_bytes"`
	CreatedAt  time.Time   `json:"created_at"`
	Settings   map[string]interface{} `json:"settings,omitempty"`
}

// IndexSpec defines index creation specification
type IndexSpec struct {
	Name       string                 `json:"name"`
	Settings   map[string]interface{} `json:"settings,omitempty"`
	Mappings   map[string]interface{} `json:"mappings,omitempty"`
	Aliases    []string               `json:"aliases,omitempty"`
}

// Role represents a security role
type Role struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Type        RoleType `json:"type"`
	Permissions []string `json:"permissions"`
	Description string   `json:"description,omitempty"`
	TenantIDs   []string `json:"tenant_ids,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// RoleSpec defines role creation specification
type RoleSpec struct {
	Name        string   `json:"name"`
	Type        RoleType `json:"type"`
	Permissions []string `json:"permissions"`
	Description string   `json:"description,omitempty"`
	TenantIDs   []string `json:"tenant_ids,omitempty"`
}

// Permission represents a system permission
type Permission struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Resource    string   `json:"resource"`
	Action      string   `json:"action"`
	Description string   `json:"description,omitempty"`
	Scope       []string `json:"scope,omitempty"`
}

// AuthToken represents an authentication token
type AuthToken struct {
	Token     string    `json:"token"`
	Type      string    `json:"type"`
	ExpiresAt time.Time `json:"expires_at"`
	Scope     []string  `json:"scope,omitempty"`
	UserID    string    `json:"user_id,omitempty"`
	TenantID  string    `json:"tenant_id,omitempty"`
}

// PasswordRotationResult represents the result of password rotation
type PasswordRotationResult struct {
	TotalUsers    int                    `json:"total_users"`
	SuccessCount  int                    `json:"success_count"`
	FailureCount  int                    `json:"failure_count"`
	Results       []PasswordRotationItem `json:"results"`
	StartedAt     time.Time              `json:"started_at"`
	CompletedAt   time.Time              `json:"completed_at"`
}

// PasswordRotationItem represents a single password rotation result
type PasswordRotationItem struct {
	UserID      string `json:"user_id"`
	Username    string `json:"username"`
	Success     bool   `json:"success"`
	NewPassword string `json:"new_password,omitempty"`
	Error       string `json:"error,omitempty"`
}

// LDAP-related entities

// LDAPConfig represents LDAP configuration
type LDAPConfig struct {
	Host         string `json:"host"`
	Port         int    `json:"port"`
	UseSSL       bool   `json:"use_ssl"`
	BaseDN       string `json:"base_dn"`
	BindDN       string `json:"bind_dn"`
	BindPassword string `json:"bind_password"`
	UserFilter   string `json:"user_filter"`
	GroupFilter  string `json:"group_filter"`
	UserBaseDN   string `json:"user_base_dn"`
	GroupBaseDN  string `json:"group_base_dn"`
	Attributes   *LDAPAttributes `json:"attributes,omitempty"`
}

// LDAPAttributes defines LDAP attribute mappings
type LDAPAttributes struct {
	Username  string `json:"username"`
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Groups    string `json:"groups"`
}

// LDAPUser represents an LDAP user
type LDAPUser struct {
	DN         string   `json:"dn"`
	Username   string   `json:"username"`
	Email      string   `json:"email"`
	FirstName  string   `json:"first_name,omitempty"`
	LastName   string   `json:"last_name,omitempty"`
	Groups     []string `json:"groups,omitempty"`
	Department string   `json:"department,omitempty"`
	Active     bool     `json:"active"`
}

// LDAPGroup represents an LDAP group
type LDAPGroup struct {
	DN          string   `json:"dn"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Members     []string `json:"members,omitempty"`
}

// LDAPTestResult represents LDAP connection test results
type LDAPTestResult struct {
	Success      bool      `json:"success"`
	Message      string    `json:"message"`
	TestedAt     time.Time `json:"tested_at"`
	ResponseTime time.Duration `json:"response_time"`
	UserCount    int       `json:"user_count,omitempty"`
	GroupCount   int       `json:"group_count,omitempty"`
}

// SyncConfig defines synchronization configuration
type SyncConfig struct {
	Enabled       bool     `json:"enabled"`
	Interval      string   `json:"interval"`
	UserBaseDN    string   `json:"user_base_dn"`
	GroupBaseDN   string   `json:"group_base_dn"`
	IncludeGroups []string `json:"include_groups,omitempty"`
	ExcludeGroups []string `json:"exclude_groups,omitempty"`
	DryRun        bool     `json:"dry_run"`
}

// SyncResult represents synchronization results
type SyncResult struct {
	ID           string    `json:"id"`
	Type         string    `json:"type"` // users, groups
	Status       string    `json:"status"`
	StartedAt    time.Time `json:"started_at"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
	TotalItems   int       `json:"total_items"`
	ProcessedItems int     `json:"processed_items"`
	CreatedItems int       `json:"created_items"`
	UpdatedItems int       `json:"updated_items"`
	SkippedItems int       `json:"skipped_items"`
	ErrorItems   int       `json:"error_items"`
	Errors       []string  `json:"errors,omitempty"`
}

// SyncStatus represents ongoing sync status
type SyncStatus struct {
	SyncID      string    `json:"sync_id"`
	Status      string    `json:"status"`
	Progress    float64   `json:"progress"` // 0.0 to 1.0
	CurrentItem string    `json:"current_item,omitempty"`
	StartedAt   time.Time `json:"started_at"`
	EstimatedCompletion *time.Time `json:"estimated_completion,omitempty"`
}

// OpenSearch-related entities

// OpenSearchConfig represents OpenSearch configuration
type OpenSearchConfig struct {
	Hosts       []string          `json:"hosts"`
	Username    string            `json:"username,omitempty"`
	Password    string            `json:"password,omitempty"`
	APIKey      string            `json:"api_key,omitempty"`
	UseSSL      bool              `json:"use_ssl"`
	CertPath    string            `json:"cert_path,omitempty"`
	KeyPath     string            `json:"key_path,omitempty"`
	CAPath      string            `json:"ca_path,omitempty"`
	SkipVerify  bool              `json:"skip_verify"`
	Timeout     time.Duration     `json:"timeout"`
	Settings    map[string]interface{} `json:"settings,omitempty"`
}

// ClusterHealth represents OpenSearch cluster health
type ClusterHealth struct {
	ClusterName         string  `json:"cluster_name"`
	Status              string  `json:"status"` // green, yellow, red
	NumberOfNodes       int     `json:"number_of_nodes"`
	NumberOfDataNodes   int     `json:"number_of_data_nodes"`
	ActivePrimaryShards int     `json:"active_primary_shards"`
	ActiveShards        int     `json:"active_shards"`
	RelocatingShards    int     `json:"relocating_shards"`
	InitializingShards  int     `json:"initializing_shards"`
	UnassignedShards    int     `json:"unassigned_shards"`
	DelayedUnassignedShards int `json:"delayed_unassigned_shards"`
	NumberOfPendingTasks int    `json:"number_of_pending_tasks"`
	TaskMaxWaitingTime  string  `json:"task_max_waiting_time"`
	ActiveShardsPercent float64 `json:"active_shards_percent"`
}

// ClusterStats represents OpenSearch cluster statistics
type ClusterStats struct {
	ClusterName   string                 `json:"cluster_name"`
	Timestamp     time.Time              `json:"timestamp"`
	NodesCount    int                    `json:"nodes_count"`
	IndicesCount  int                    `json:"indices_count"`
	DocsCount     int64                  `json:"docs_count"`
	StoreSize     int64                  `json:"store_size_bytes"`
	MemoryUsed    int64                  `json:"memory_used_bytes"`
	CPUUsed       float64                `json:"cpu_used_percent"`
	DiskUsed      int64                  `json:"disk_used_bytes"`
	DiskTotal     int64                  `json:"disk_total_bytes"`
	Details       map[string]interface{} `json:"details,omitempty"`
}

// OpenSearchIndex represents an OpenSearch index
type OpenSearchIndex struct {
	Name      string                 `json:"name"`
	Health    string                 `json:"health"`
	Status    string                 `json:"status"`
	UUID      string                 `json:"uuid"`
	Primary   int                    `json:"primary"`
	Replica   int                    `json:"replica"`
	DocsCount int64                  `json:"docs_count"`
	DocsDeleted int64                `json:"docs_deleted"`
	StoreSize int64                  `json:"store_size_bytes"`
	PrimaryStoreSize int64          `json:"primary_store_size_bytes"`
	CreationDate time.Time           `json:"creation_date"`
	Settings  map[string]interface{} `json:"settings,omitempty"`
	Mappings  map[string]interface{} `json:"mappings,omitempty"`
}

// OpenSearchIndexSpec defines OpenSearch index creation specification
type OpenSearchIndexSpec struct {
	Name     string                 `json:"name"`
	Settings map[string]interface{} `json:"settings,omitempty"`
	Mappings map[string]interface{} `json:"mappings,omitempty"`
	Aliases  map[string]interface{} `json:"aliases,omitempty"`
}

// IndexHealth represents index health information
type IndexHealth struct {
	Index               string  `json:"index"`
	Status              string  `json:"status"`
	NumberOfShards      int     `json:"number_of_shards"`
	NumberOfReplicas    int     `json:"number_of_replicas"`
	ActivePrimaryShards int     `json:"active_primary_shards"`
	ActiveShards        int     `json:"active_shards"`
	RelocatingShards    int     `json:"relocating_shards"`
	InitializingShards  int     `json:"initializing_shards"`
	UnassignedShards    int     `json:"unassigned_shards"`
	ActiveShardsPercent float64 `json:"active_shards_percent"`
}

// IndexTemplate represents an OpenSearch index template
type IndexTemplate struct {
	Name           string                 `json:"name"`
	IndexPatterns  []string               `json:"index_patterns"`
	Template       *IndexTemplateSpec     `json:"template,omitempty"`
	Priority       int                    `json:"priority"`
	Version        int                    `json:"version,omitempty"`
	Metadata       map[string]interface{} `json:"_meta,omitempty"`
	ComposedOf     []string               `json:"composed_of,omitempty"`
}

// IndexTemplateSpec defines the template specification
type IndexTemplateSpec struct {
	Settings map[string]interface{} `json:"settings,omitempty"`
	Mappings map[string]interface{} `json:"mappings,omitempty"`
	Aliases  map[string]interface{} `json:"aliases,omitempty"`
}

// OpenSearchRole represents an OpenSearch security role
type OpenSearchRole struct {
	Name            string              `json:"name"`
	ClusterPermissions []string         `json:"cluster_permissions,omitempty"`
	IndexPermissions []IndexPermission   `json:"index_permissions,omitempty"`
	TenantPermissions []TenantPermission `json:"tenant_permissions,omitempty"`
	Description     string              `json:"description,omitempty"`
}

// OpenSearchRoleSpec defines OpenSearch role specification
type OpenSearchRoleSpec struct {
	ClusterPermissions []string         `json:"cluster_permissions,omitempty"`
	IndexPermissions []IndexPermission   `json:"index_permissions,omitempty"`
	TenantPermissions []TenantPermission `json:"tenant_permissions,omitempty"`
	Description     string              `json:"description,omitempty"`
}

// IndexPermission represents index-level permissions
type IndexPermission struct {
	IndexPatterns     []string `json:"index_patterns"`
	DocumentLevelSecurity string `json:"dls,omitempty"`
	FieldLevelSecurity []string `json:"fls,omitempty"`
	AllowedActions    []string `json:"allowed_actions"`
}

// TenantPermission represents tenant-level permissions
type TenantPermission struct {
	TenantPatterns []string `json:"tenant_patterns"`
	AllowedActions []string `json:"allowed_actions"`
}

// SearchQuery represents a search query
type SearchQuery struct {
	Index   string                 `json:"index"`
	Query   map[string]interface{} `json:"query"`
	Sort    []map[string]interface{} `json:"sort,omitempty"`
	From    int                    `json:"from,omitempty"`
	Size    int                    `json:"size,omitempty"`
	Source  []string               `json:"_source,omitempty"`
	Timeout string                 `json:"timeout,omitempty"`
}

// SearchResult represents search results
type SearchResult struct {
	TookMs      int                      `json:"took"`
	TimedOut    bool                     `json:"timed_out"`
	TotalHits   int64                    `json:"total_hits"`
	MaxScore    float64                  `json:"max_score"`
	Hits        []SearchHit              `json:"hits"`
	Aggregations map[string]interface{}  `json:"aggregations,omitempty"`
	ScrollID    string                   `json:"_scroll_id,omitempty"`
}

// SearchHit represents a single search result
type SearchHit struct {
	Index  string                 `json:"_index"`
	Type   string                 `json:"_type"`
	ID     string                 `json:"_id"`
	Score  float64                `json:"_score"`
	Source map[string]interface{} `json:"_source"`
}

// AggregationQuery represents an aggregation query
type AggregationQuery struct {
	Index        string                 `json:"index"`
	Query        map[string]interface{} `json:"query,omitempty"`
	Aggregations map[string]interface{} `json:"aggregations"`
	Size         int                    `json:"size,omitempty"`
}

// AggregationResult represents aggregation results
type AggregationResult struct {
	TookMs       int                    `json:"took"`
	TimedOut     bool                   `json:"timed_out"`
	TotalHits    int64                  `json:"total_hits"`
	Aggregations map[string]interface{} `json:"aggregations"`
}

// Vulnerability and scanning entities

// ScanTarget represents a vulnerability scan target
type ScanTarget struct {
	Type        string   `json:"type"` // host, network, application
	Targets     []string `json:"targets"`
	Credentials map[string]string `json:"credentials,omitempty"`
	Options     map[string]interface{} `json:"options,omitempty"`
}

// VulnerabilityScan represents a vulnerability scan
type VulnerabilityScan struct {
	ID          string      `json:"id"`
	TenantID    string      `json:"tenant_id"`
	Target      *ScanTarget `json:"target"`
	Status      string      `json:"status"`
	StartedAt   time.Time   `json:"started_at"`
	CompletedAt *time.Time  `json:"completed_at,omitempty"`
	Progress    float64     `json:"progress"`
	Results     *VulnerabilityReport `json:"results,omitempty"`
}

// VulnerabilityReport represents vulnerability scan results
type VulnerabilityReport struct {
	ScanID        string                 `json:"scan_id"`
	GeneratedAt   time.Time              `json:"generated_at"`
	Summary       *VulnerabilitySummary  `json:"summary"`
	Vulnerabilities []*Vulnerability     `json:"vulnerabilities"`
	Assets        []*ScannedAsset        `json:"assets"`
	Recommendations []string             `json:"recommendations,omitempty"`
}

// VulnerabilitySummary provides vulnerability statistics
type VulnerabilitySummary struct {
	TotalVulnerabilities int            `json:"total_vulnerabilities"`
	BySeverity          map[string]int `json:"by_severity"`
	ByCategory          map[string]int `json:"by_category"`
	Critical            int            `json:"critical"`
	High                int            `json:"high"`
	Medium              int            `json:"medium"`
	Low                 int            `json:"low"`
	Info                int            `json:"info"`
}

// Vulnerability represents a security vulnerability
type Vulnerability struct {
	ID          string    `json:"id"`
	CVE         string    `json:"cve,omitempty"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Score       float64   `json:"score,omitempty"`
	Category    string    `json:"category"`
	Asset       string    `json:"asset"`
	Component   string    `json:"component,omitempty"`
	FirstFound  time.Time `json:"first_found"`
	LastSeen    time.Time `json:"last_seen"`
	Status      string    `json:"status"`
	Solution    string    `json:"solution,omitempty"`
	References  []string  `json:"references,omitempty"`
}

// ScannedAsset represents an asset that was scanned
type ScannedAsset struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Type            string   `json:"type"`
	IP              string   `json:"ip,omitempty"`
	OS              string   `json:"os,omitempty"`
	Services        []string `json:"services,omitempty"`
	Vulnerabilities int      `json:"vulnerabilities"`
	RiskScore       float64  `json:"risk_score"`
}

// VulnerabilityTrends represents vulnerability trends over time
type VulnerabilityTrends struct {
	TenantID    string                `json:"tenant_id"`
	TimeRange   *TimeRange            `json:"time_range"`
	TrendData   map[string][]int      `json:"trend_data"` // date -> counts
	Summary     *VulnerabilitySummary `json:"summary"`
	Comparison  *TrendComparison      `json:"comparison,omitempty"`
}

// TrendComparison represents trend comparison data
type TrendComparison struct {
	PreviousPeriod *VulnerabilitySummary `json:"previous_period"`
	Change         map[string]int        `json:"change"`
	PercentChange  map[string]float64    `json:"percent_change"`
}

// Compliance entities

// ComplianceFramework represents a compliance framework
type ComplianceFramework struct {
	ID           string              `json:"id"`
	Name         string              `json:"name"`
	Version      string              `json:"version"`
	Description  string              `json:"description"`
	Controls     []*ComplianceControl `json:"controls"`
	Categories   []string            `json:"categories"`
	Applicability map[string]interface{} `json:"applicability,omitempty"`
}

// ComplianceControl represents a compliance control
type ComplianceControl struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Category    string   `json:"category"`
	Requirements []string `json:"requirements"`
	Tests       []string `json:"tests"`
	Automated   bool     `json:"automated"`
}

// ComplianceCheckResult represents compliance check results
type ComplianceCheckResult struct {
	FrameworkID string                   `json:"framework_id"`
	TenantID    string                   `json:"tenant_id"`
	CheckedAt   time.Time                `json:"checked_at"`
	OverallScore float64                 `json:"overall_score"`
	Status      string                   `json:"status"`
	Results     []*ControlCheckResult    `json:"results"`
	Summary     *ComplianceSummary       `json:"summary"`
}

// ControlCheckResult represents a single control check result
type ControlCheckResult struct {
	ControlID   string    `json:"control_id"`
	Status      string    `json:"status"` // passed, failed, warning, not_applicable
	Score       float64   `json:"score"`
	Evidence    []string  `json:"evidence,omitempty"`
	Issues      []string  `json:"issues,omitempty"`
	CheckedAt   time.Time `json:"checked_at"`
}

// ComplianceSummary provides compliance statistics
type ComplianceSummary struct {
	TotalControls    int            `json:"total_controls"`
	PassedControls   int            `json:"passed_controls"`
	FailedControls   int            `json:"failed_controls"`
	WarningControls  int            `json:"warning_controls"`
	SkippedControls  int            `json:"skipped_controls"`
	ByCategory       map[string]ComplianceCategoryResult `json:"by_category"`
	ComplianceScore  float64        `json:"compliance_score"`
}

// ComplianceCategoryResult represents compliance results by category
type ComplianceCategoryResult struct {
	Total   int     `json:"total"`
	Passed  int     `json:"passed"`
	Failed  int     `json:"failed"`
	Warning int     `json:"warning"`
	Score   float64 `json:"score"`
}

// ComplianceStatus represents overall compliance status
type ComplianceStatus struct {
	TenantID       string                     `json:"tenant_id"`
	LastChecked    time.Time                  `json:"last_checked"`
	OverallScore   float64                    `json:"overall_score"`
	Status         string                     `json:"status"`
	Frameworks     map[string]float64         `json:"frameworks"` // framework -> score
	TopIssues      []string                   `json:"top_issues"`
	Recommendations []string                  `json:"recommendations"`
	TrendData      map[string][]float64       `json:"trend_data,omitempty"`
}

// ComplianceReport represents a compliance report
type ComplianceReport struct {
	ID          string                `json:"id"`
	TenantID    string                `json:"tenant_id"`
	Title       string                `json:"title"`
	Framework   string                `json:"framework"`
	GeneratedAt time.Time             `json:"generated_at"`
	GeneratedBy string                `json:"generated_by"`
	TimeRange   *TimeRange            `json:"time_range"`
	Summary     *ComplianceSummary    `json:"summary"`
	Sections    []*ReportSection      `json:"sections"`
	Recommendations []string          `json:"recommendations"`
	Executive   *ExecutiveSummary     `json:"executive,omitempty"`
}

// ComplianceReportSpec defines compliance report generation specification
type ComplianceReportSpec struct {
	Title       string     `json:"title"`
	Framework   string     `json:"framework"`
	TimeRange   *TimeRange `json:"time_range"`
	Sections    []string   `json:"sections"`
	Format      string     `json:"format"` // pdf, html, json
	Recipients  []string   `json:"recipients,omitempty"`
	Schedule    string     `json:"schedule,omitempty"`
}

// ReportSection represents a section in a report
type ReportSection struct {
	ID      string                 `json:"id"`
	Title   string                 `json:"title"`
	Content string                 `json:"content"`
	Data    map[string]interface{} `json:"data,omitempty"`
	Charts  []ChartData            `json:"charts,omitempty"`
}

// ExecutiveSummary represents an executive summary
type ExecutiveSummary struct {
	OverallRisk     string   `json:"overall_risk"`
	KeyFindings     []string `json:"key_findings"`
	CriticalIssues  []string `json:"critical_issues"`
	Recommendations []string `json:"recommendations"`
	NextSteps       []string `json:"next_steps"`
}

// ChartData represents chart data for reports
type ChartData struct {
	Type   string                 `json:"type"`
	Title  string                 `json:"title"`
	Data   map[string]interface{} `json:"data"`
	Config map[string]interface{} `json:"config,omitempty"`
}

// ReportSpec defines general report specification
type ReportSpec struct {
	Type       string                 `json:"type"`
	Title      string                 `json:"title"`
	TimeRange  *TimeRange             `json:"time_range"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
	Format     string                 `json:"format"`
	Recipients []string               `json:"recipients,omitempty"`
}

// Notification entities

// Notification represents a notification message
type Notification struct {
	ID        string           `json:"id"`
	Type      NotificationType `json:"type"`
	Recipient string           `json:"recipient"`
	Subject   string           `json:"subject"`
	Content   string           `json:"content"`
	Data      map[string]interface{} `json:"data,omitempty"`
	CreatedAt time.Time        `json:"created_at"`
	SentAt    *time.Time       `json:"sent_at,omitempty"`
	Status    NotificationStatus `json:"status"`
	Retries   int              `json:"retries"`
	Error     string           `json:"error,omitempty"`
}

// NotificationRule represents a notification rule
type NotificationRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	TenantID    string                 `json:"tenant_id"`
	Enabled     bool                   `json:"enabled"`
	Conditions  map[string]interface{} `json:"conditions"`
	Actions     []*NotificationAction  `json:"actions"`
	Cooldown    time.Duration          `json:"cooldown"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	LastTriggered *time.Time           `json:"last_triggered,omitempty"`
}

// NotificationAction represents a notification action
type NotificationAction struct {
	Type       NotificationType       `json:"type"`
	Recipients []string               `json:"recipients"`
	Template   string                 `json:"template"`
	Config     map[string]interface{} `json:"config,omitempty"`
}

// NotificationHistory represents notification history
type NotificationHistory struct {
	ID           string    `json:"id"`
	RuleID       string    `json:"rule_id"`
	NotificationID string  `json:"notification_id"`
	TriggerEvent string    `json:"trigger_event"`
	TriggeredAt  time.Time `json:"triggered_at"`
	Success      bool      `json:"success"`
	Error        string    `json:"error,omitempty"`
}

// EmailNotification represents an email notification
type EmailNotification struct {
	To      []string `json:"to"`
	CC      []string `json:"cc,omitempty"`
	BCC     []string `json:"bcc,omitempty"`
	Subject string   `json:"subject"`
	Body    string   `json:"body"`
	HTML    bool     `json:"html"`
	Attachments []EmailAttachment `json:"attachments,omitempty"`
}

// EmailAttachment represents an email attachment
type EmailAttachment struct {
	Name        string `json:"name"`
	Content     []byte `json:"content"`
	ContentType string `json:"content_type"`
}

// SMSNotification represents an SMS notification
type SMSNotification struct {
	To      string `json:"to"`
	Message string `json:"message"`
}

// SlackNotification represents a Slack notification
type SlackNotification struct {
	Channel     string                 `json:"channel"`
	Message     string                 `json:"message"`
	Username    string                 `json:"username,omitempty"`
	IconEmoji   string                 `json:"icon_emoji,omitempty"`
	Attachments []SlackAttachment      `json:"attachments,omitempty"`
	Blocks      []map[string]interface{} `json:"blocks,omitempty"`
}

// SlackAttachment represents a Slack attachment
type SlackAttachment struct {
	Title     string `json:"title,omitempty"`
	Text      string `json:"text,omitempty"`
	Color     string `json:"color,omitempty"`
	Fields    []SlackField `json:"fields,omitempty"`
	Timestamp int64  `json:"ts,omitempty"`
}

// SlackField represents a Slack field
type SlackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

// WebhookNotification represents a webhook notification
type WebhookNotification struct {
	URL     string                 `json:"url"`
	Method  string                 `json:"method"`
	Headers map[string]string      `json:"headers,omitempty"`
	Body    map[string]interface{} `json:"body"`
	Timeout time.Duration          `json:"timeout,omitempty"`
}

// NotificationConfig represents notification provider configuration
type NotificationConfig struct {
	Type     NotificationType       `json:"type"`
	Enabled  bool                   `json:"enabled"`
	Settings map[string]interface{} `json:"settings"`
}

// Alert rule entities

// AlertRule represents an alert rule
type AlertRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	TenantID    string                 `json:"tenant_id"`
	Enabled     bool                   `json:"enabled"`
	Description string                 `json:"description,omitempty"`
	Query       string                 `json:"query"`
	Conditions  []*AlertCondition      `json:"conditions"`
	Actions     []*AlertAction         `json:"actions"`
	Severity    AlertSeverity          `json:"severity"`
	Tags        []string               `json:"tags,omitempty"`
	Schedule    *AlertSchedule         `json:"schedule"`
	Throttle    time.Duration          `json:"throttle,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	LastRun     *time.Time             `json:"last_run,omitempty"`
}

// AlertCondition represents an alert condition
type AlertCondition struct {
	Field     string      `json:"field"`
	Operator  string      `json:"operator"` // gt, lt, eq, ne, contains, etc.
	Value     interface{} `json:"value"`
	Threshold float64     `json:"threshold,omitempty"`
	TimeWindow string     `json:"time_window,omitempty"`
}

// AlertAction represents an action to take when alert fires
type AlertAction struct {
	Type       string                 `json:"type"`
	Parameters map[string]interface{} `json:"parameters"`
	Enabled    bool                   `json:"enabled"`
}

// AlertSchedule represents alert evaluation schedule
type AlertSchedule struct {
	Interval string `json:"interval"`
	Timezone string `json:"timezone,omitempty"`
	Enabled  bool   `json:"enabled"`
}

// AlertTestData represents test data for alert rules
type AlertTestData struct {
	Query     string                 `json:"query"`
	TimeRange *TimeRange             `json:"time_range"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

// AlertRuleTestResult represents alert rule test results
type AlertRuleTestResult struct {
	RuleID     string                 `json:"rule_id"`
	TestedAt   time.Time              `json:"tested_at"`
	Triggered  bool                   `json:"triggered"`
	MatchCount int                    `json:"match_count"`
	Results    []map[string]interface{} `json:"results,omitempty"`
	Error      string                 `json:"error,omitempty"`
}

// CorrelationRule represents an alert correlation rule
type CorrelationRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	TenantID    string                 `json:"tenant_id"`
	Enabled     bool                   `json:"enabled"`
	Description string                 `json:"description,omitempty"`
	Patterns    []*CorrelationPattern  `json:"patterns"`
	TimeWindow  time.Duration          `json:"time_window"`
	Threshold   int                    `json:"threshold"`
	Actions     []*AlertAction         `json:"actions"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// CorrelationPattern represents a pattern for correlation
type CorrelationPattern struct {
	AlertType string                 `json:"alert_type"`
	Filters   map[string]interface{} `json:"filters"`
	Weight    float64                `json:"weight"`
}

// Configuration entities

// Configuration represents a system configuration
type Configuration struct {
	ID        string            `json:"id"`
	Type      ConfigurationType `json:"type"`
	Name      string            `json:"name"`
	Data      map[string]interface{} `json:"data"`
	Version   int               `json:"version"`
	Status    ConfigurationStatus `json:"status"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
	CreatedBy string            `json:"created_by"`
	UpdatedBy string            `json:"updated_by"`
}

// SystemConfiguration represents system-wide configuration
type SystemConfiguration struct {
	LogLevel     string                 `json:"log_level"`
	Debug        bool                   `json:"debug"`
	Features     map[string]bool        `json:"features"`
	Limits       map[string]int         `json:"limits"`
	Retention    map[string]string      `json:"retention"`
	Security     *SecurityPolicy        `json:"security"`
	Integrations map[string]interface{} `json:"integrations"`
	Advanced     map[string]interface{} `json:"advanced,omitempty"`
}

// SecurityPolicy represents security policy configuration
type SecurityPolicy struct {
	PasswordPolicy    *PasswordPolicy    `json:"password_policy"`
	SessionTimeout    time.Duration      `json:"session_timeout"`
	MFARequired       bool               `json:"mfa_required"`
	IPWhitelist       []string           `json:"ip_whitelist,omitempty"`
	EncryptionConfig  *EncryptionConfig  `json:"encryption_config"`
	AccessControl     *AccessControl     `json:"access_control"`
	AuditLevel        string             `json:"audit_level"`
	ComplianceConfig  *ComplianceConfig  `json:"compliance_config,omitempty"`
}

// PasswordPolicy represents password policy settings
type PasswordPolicy struct {
	MinLength        int           `json:"min_length"`
	RequireUppercase bool          `json:"require_uppercase"`
	RequireLowercase bool          `json:"require_lowercase"`
	RequireNumbers   bool          `json:"require_numbers"`
	RequireSymbols   bool          `json:"require_symbols"`
	MaxAge           time.Duration `json:"max_age"`
	MinAge           time.Duration `json:"min_age"`
	HistorySize      int           `json:"history_size"`
	LockoutThreshold int           `json:"lockout_threshold"`
	LockoutDuration  time.Duration `json:"lockout_duration"`
}

// EncryptionConfig represents encryption configuration
type EncryptionConfig struct {
	Algorithm        string            `json:"algorithm"`
	KeySize          int               `json:"key_size"`
	EncryptAtRest    bool              `json:"encrypt_at_rest"`
	EncryptInTransit bool              `json:"encrypt_in_transit"`
	KeyRotationDays  int               `json:"key_rotation_days"`
	Settings         map[string]interface{} `json:"settings,omitempty"`
}

// AccessControl represents access control configuration
type AccessControl struct {
	DefaultPermissions []string          `json:"default_permissions"`
	RoleBasedAccess    bool              `json:"role_based_access"`
	ResourcePolicies   map[string]string `json:"resource_policies"`
	IPRestrictions     []IPRestriction   `json:"ip_restrictions,omitempty"`
	TimeRestrictions   []TimeRestriction `json:"time_restrictions,omitempty"`
}

// IPRestriction represents IP-based access restriction
type IPRestriction struct {
	Pattern string   `json:"pattern"`
	Action  string   `json:"action"` // allow, deny
	Users   []string `json:"users,omitempty"`
	Roles   []string `json:"roles,omitempty"`
}

// TimeRestriction represents time-based access restriction
type TimeRestriction struct {
	Days      []string `json:"days"`      // monday, tuesday, etc.
	StartTime string   `json:"start_time"` // HH:MM
	EndTime   string   `json:"end_time"`   // HH:MM
	Timezone  string   `json:"timezone"`
	Users     []string `json:"users,omitempty"`
	Roles     []string `json:"roles,omitempty"`
}

// ComplianceConfig represents compliance configuration
type ComplianceConfig struct {
	Frameworks      []string          `json:"frameworks"`
	AutoReporting   bool              `json:"auto_reporting"`
	ReportSchedule  string            `json:"report_schedule"`
	RetentionPeriod time.Duration     `json:"retention_period"`
	Settings        map[string]interface{} `json:"settings,omitempty"`
}

// ConfigurationVersion represents a configuration version
type ConfigurationVersion struct {
	ID           string    `json:"id"`
	ConfigID     string    `json:"config_id"`
	Version      int       `json:"version"`
	Data         map[string]interface{} `json:"data"`
	ChangeLog    string    `json:"change_log,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	CreatedBy    string    `json:"created_by"`
	Tags         []string  `json:"tags,omitempty"`
}

// ConfigTemplate represents a configuration template
type ConfigTemplate struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        ConfigurationType      `json:"type"`
	Description string                 `json:"description,omitempty"`
	Template    map[string]interface{} `json:"template"`
	Variables   []*TemplateVariable    `json:"variables,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Version     string                 `json:"version"`
}

// TemplateVariable represents a template variable
type TemplateVariable struct {
	Name         string      `json:"name"`
	Type         string      `json:"type"`
	Description  string      `json:"description,omitempty"`
	DefaultValue interface{} `json:"default_value,omitempty"`
	Required     bool        `json:"required"`
	Options      []string    `json:"options,omitempty"`
}

// ConfigBackup represents a configuration backup
type ConfigBackup struct {
	ID          string    `json:"id"`
	Scope       *ConfigBackupScope `json:"scope"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by"`
	Size        int64     `json:"size_bytes"`
	Compressed  bool      `json:"compressed"`
	Encrypted   bool      `json:"encrypted"`
	Status      string    `json:"status"`
	Location    string    `json:"location"`
	Checksum    string    `json:"checksum"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// ConfigBackupScope defines the scope of a configuration backup
type ConfigBackupScope struct {
	Type        string   `json:"type"` // system, tenant, user
	TenantIDs   []string `json:"tenant_ids,omitempty"`
	ConfigTypes []ConfigurationType `json:"config_types,omitempty"`
	IncludeData bool     `json:"include_data"`
}

// Backup and restore entities

// BackupSpec represents backup specification
type BackupSpec struct {
	Type        BackupType `json:"type"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Scope       *BackupScope `json:"scope"`
	Compression bool       `json:"compression"`
	Encryption  bool       `json:"encryption"`
	Schedule    string     `json:"schedule,omitempty"`
	Retention   time.Duration `json:"retention"`
}

// BackupScope defines backup scope
type BackupScope struct {
	TenantIDs []string `json:"tenant_ids,omitempty"`
	Indices   []string `json:"indices,omitempty"`
	DataTypes []string `json:"data_types,omitempty"`
}

// Backup represents a backup
type Backup struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Type        BackupType    `json:"type"`
	Status      BackupStatus  `json:"status"`
	CreatedAt   time.Time     `json:"created_at"`
	CompletedAt *time.Time    `json:"completed_at,omitempty"`
	Size        int64         `json:"size_bytes"`
	Location    string        `json:"location"`
	Compressed  bool          `json:"compressed"`
	Encrypted   bool          `json:"encrypted"`
	Checksum    string        `json:"checksum"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// RestoreOptions represents restore options
type RestoreOptions struct {
	TargetLocation string            `json:"target_location,omitempty"`
	Overwrite      bool              `json:"overwrite"`
	Filters        map[string]string `json:"filters,omitempty"`
	DryRun         bool              `json:"dry_run"`
}

// BackupValidation represents backup validation results
type BackupValidation struct {
	BackupID    string    `json:"backup_id"`
	Valid       bool      `json:"valid"`
	ValidatedAt time.Time `json:"validated_at"`
	Issues      []string  `json:"issues,omitempty"`
	Checksum    string    `json:"checksum"`
	Size        int64     `json:"size_bytes"`
}

// Monitoring and metrics entities

// Metrics represents collected metrics
type Metrics struct {
	Source      string                 `json:"source"`
	CollectedAt time.Time              `json:"collected_at"`
	Data        map[string]interface{} `json:"data"`
	Tags        map[string]string      `json:"tags,omitempty"`
}

// MetricData represents a single metric data point
type MetricData struct {
	Name      string            `json:"name"`
	Value     float64           `json:"value"`
	Unit      string            `json:"unit,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
	Tags      map[string]string `json:"tags,omitempty"`
}

// MetricQuery represents a metrics query
type MetricQuery struct {
	Metrics   []string          `json:"metrics"`
	TimeRange *TimeRange        `json:"time_range"`
	Filters   map[string]string `json:"filters,omitempty"`
	GroupBy   []string          `json:"group_by,omitempty"`
	Aggregate string            `json:"aggregate,omitempty"`
}

// MetricResult represents query results
type MetricResult struct {
	Query     *MetricQuery           `json:"query"`
	Data      []MetricDataPoint      `json:"data"`
	Summary   map[string]interface{} `json:"summary,omitempty"`
	ExecutedAt time.Time             `json:"executed_at"`
}

// MetricDataPoint represents a metric data point in results
type MetricDataPoint struct {
	Timestamp time.Time         `json:"timestamp"`
	Values    map[string]float64 `json:"values"`
	Tags      map[string]string `json:"tags,omitempty"`
}

// Dashboard represents a monitoring dashboard
type Dashboard struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	TenantID    string           `json:"tenant_id,omitempty"`
	Widgets     []*DashboardWidget `json:"widgets"`
	Layout      *DashboardLayout `json:"layout,omitempty"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
	CreatedBy   string           `json:"created_by"`
	Shared      bool             `json:"shared"`
	Tags        []string         `json:"tags,omitempty"`
}

// DashboardWidget represents a dashboard widget
type DashboardWidget struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Title     string                 `json:"title"`
	Query     *MetricQuery           `json:"query,omitempty"`
	Config    map[string]interface{} `json:"config,omitempty"`
	Position  *WidgetPosition        `json:"position,omitempty"`
}

// WidgetPosition represents widget position on dashboard
type WidgetPosition struct {
	X      int `json:"x"`
	Y      int `json:"y"`
	Width  int `json:"width"`
	Height int `json:"height"`
}

// DashboardLayout represents dashboard layout
type DashboardLayout struct {
	Columns int    `json:"columns"`
	Rows    int    `json:"rows"`
	Type    string `json:"type"` // grid, flex, etc.
}

// SystemHealth represents system health information
type SystemHealth struct {
	Status      string                 `json:"status"` // healthy, degraded, unhealthy
	CheckedAt   time.Time              `json:"checked_at"`
	Components  map[string]ComponentHealth `json:"components"`
	Uptime      time.Duration          `json:"uptime"`
	Version     string                 `json:"version"`
	Environment string                 `json:"environment"`
	Metrics     map[string]interface{} `json:"metrics,omitempty"`
}

// ComponentHealth represents health of a system component
type ComponentHealth struct {
	Status      string                 `json:"status"`
	Message     string                 `json:"message,omitempty"`
	CheckedAt   time.Time              `json:"checked_at"`
	ResponseTime time.Duration         `json:"response_time,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// Audit and security entities

// SecurityAuditEvent represents a security audit event
type SecurityAuditEvent struct {
	ID          string            `json:"id"`
	TenantID    string            `json:"tenant_id,omitempty"`
	UserID      string            `json:"user_id,omitempty"`
	EventType   SecurityEventType `json:"event_type"`
	Severity    EventSeverity     `json:"severity"`
	Resource    string            `json:"resource"`
	Action      string            `json:"action"`
	Result      string            `json:"result"` // success, failure, warning
	Message     string            `json:"message"`
	SourceIP    string            `json:"source_ip,omitempty"`
	UserAgent   string            `json:"user_agent,omitempty"`
	Timestamp   time.Time         `json:"timestamp"`
	Details     map[string]interface{} `json:"details,omitempty"`
	SessionID   string            `json:"session_id,omitempty"`
}

// SecurityEvent represents a generic security event
type SecurityEvent struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Severity  string                 `json:"severity"`
	Source    string                 `json:"source"`
	Target    string                 `json:"target,omitempty"`
	Action    string                 `json:"action"`
	Result    string                 `json:"result"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

// SecretData represents secret data with metadata
type SecretData struct {
	Value     string                 `json:"value"`
	Type      string                 `json:"type"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
	ExpiresAt *time.Time             `json:"expires_at,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	Encrypted bool                   `json:"encrypted"`
}

// SecretMetadata represents secret metadata without the actual secret
type SecretMetadata struct {
	Key       string                 `json:"key"`
	Type      string                 `json:"type"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
	ExpiresAt *time.Time             `json:"expires_at,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	Size      int                    `json:"size"`
}

// Infrastructure entities

// HTTPResponse represents an HTTP response
type HTTPResponse struct {
	StatusCode int                    `json:"status_code"`
	Headers    map[string][]string    `json:"headers"`
	Body       []byte                 `json:"body"`
	Duration   time.Duration          `json:"duration"`
	URL        string                 `json:"url"`
}

// Credentials represents generic credentials
type Credentials struct {
	Type     string                 `json:"type"`
	Username string                 `json:"username,omitempty"`
	Password string                 `json:"password,omitempty"`
	Token    string                 `json:"token,omitempty"`
	Data     map[string]interface{} `json:"data,omitempty"`
}
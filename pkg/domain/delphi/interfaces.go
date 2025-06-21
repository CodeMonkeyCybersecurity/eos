// Package delphi defines domain interfaces for security monitoring and tenant management
package delphi

import (
	"context"
	"time"
)

// Core service interfaces for security monitoring platform

// SecurityMonitoringService defines security monitoring and alerting operations
type SecurityMonitoringService interface {
	// Tenant management
	CreateTenant(ctx context.Context, spec *TenantSpec) (*Tenant, error)
	GetTenant(ctx context.Context, tenantID string) (*Tenant, error)
	ListTenants(ctx context.Context, filter *TenantFilter) ([]*Tenant, error)
	UpdateTenant(ctx context.Context, tenantID string, spec *TenantSpec) error
	DeleteTenant(ctx context.Context, tenantID string) error

	// Tenant provisioning
	ProvisionTenant(ctx context.Context, spec *TenantSpec) (*TenantProvisionResult, error)
	GetProvisioningStatus(ctx context.Context, provisionID string) (*ProvisioningStatus, error)

	// Security monitoring
	GetSecurityAlerts(ctx context.Context, tenantID string, filter *AlertFilter) ([]*SecurityAlert, error)
	GetSecurityDashboard(ctx context.Context, tenantID string) (*SecurityDashboard, error)
	GetThreatIntelligence(ctx context.Context, tenantID string) (*ThreatIntelligence, error)

	// Compliance and reporting
	GenerateComplianceReport(ctx context.Context, tenantID string, spec *ReportSpec) (*ComplianceReport, error)
	GetSecurityMetrics(ctx context.Context, tenantID string, timeRange *TimeRange) (*SecurityMetrics, error)
}

// WazuhManager defines Wazuh platform management operations
type WazuhManager interface {
	// Authentication and connection
	Authenticate(ctx context.Context, credentials *WazuhCredentials) (*AuthToken, error)
	ValidateConnection(ctx context.Context) error
	RefreshToken(ctx context.Context, token *AuthToken) (*AuthToken, error)

	// Index and tenant operations
	CreateIndex(ctx context.Context, indexSpec *IndexSpec) (*Index, error)
	DeleteIndex(ctx context.Context, indexName string) error
	GetIndex(ctx context.Context, indexName string) (*Index, error)
	ListIndices(ctx context.Context, filter *IndexFilter) ([]*Index, error)

	// Role and security management
	CreateRole(ctx context.Context, roleSpec *RoleSpec) (*Role, error)
	UpdateRole(ctx context.Context, roleName string, roleSpec *RoleSpec) error
	DeleteRole(ctx context.Context, roleName string) error
	GetRole(ctx context.Context, roleName string) (*Role, error)
	ListRoles(ctx context.Context, filter *RoleFilter) ([]*Role, error)

	// Agent management
	RegisterAgent(ctx context.Context, agentSpec *AgentSpec) (*Agent, error)
	GetAgent(ctx context.Context, agentID string) (*Agent, error)
	ListAgents(ctx context.Context, filter *AgentFilter) ([]*Agent, error)
	UpdateAgentConfig(ctx context.Context, agentID string, config *AgentConfig) error
	RemoveAgent(ctx context.Context, agentID string) error

	// Configuration management
	GetConfiguration(ctx context.Context) (*WazuhConfiguration, error)
	UpdateConfiguration(ctx context.Context, config *WazuhConfiguration) error
	ValidateConfiguration(ctx context.Context, config *WazuhConfiguration) error
}

// UserManagementService defines user and authentication operations
type UserManagementService interface {
	// User lifecycle
	CreateUser(ctx context.Context, userSpec *UserSpec) (*User, error)
	GetUser(ctx context.Context, userID string) (*User, error)
	UpdateUser(ctx context.Context, userID string, userSpec *UserSpec) error
	DeleteUser(ctx context.Context, userID string) error
	ListUsers(ctx context.Context, filter *UserFilter) ([]*User, error)

	// Authentication
	AuthenticateUser(ctx context.Context, credentials *UserCredentials) (*UserSession, error)
	ValidateSession(ctx context.Context, sessionID string) (*UserSession, error)
	RefreshSession(ctx context.Context, sessionID string) (*UserSession, error)
	RevokeSession(ctx context.Context, sessionID string) error

	// Password management
	ChangePassword(ctx context.Context, userID string, oldPassword, newPassword string) error
	ResetPassword(ctx context.Context, userID string) (string, error)
	RotatePasswords(ctx context.Context, filter *UserFilter) (*PasswordRotationResult, error)

	// Role and permission management
	AssignRole(ctx context.Context, userID, roleID string) error
	RevokeRole(ctx context.Context, userID, roleID string) error
	GetUserPermissions(ctx context.Context, userID string) ([]*Permission, error)
}

// LDAPService defines LDAP integration operations
type LDAPService interface {
	// Connection and configuration
	Connect(ctx context.Context, config *LDAPConfig) error
	ValidateConnection(ctx context.Context) error
	Disconnect(ctx context.Context) error
	TestConfiguration(ctx context.Context, config *LDAPConfig) (*LDAPTestResult, error)

	// User operations
	SearchUsers(ctx context.Context, filter *LDAPUserFilter) ([]*LDAPUser, error)
	GetUser(ctx context.Context, userDN string) (*LDAPUser, error)
	AuthenticateUser(ctx context.Context, userDN, password string) error

	// Group operations
	SearchGroups(ctx context.Context, filter *LDAPGroupFilter) ([]*LDAPGroup, error)
	GetGroup(ctx context.Context, groupDN string) (*LDAPGroup, error)
	GetUserGroups(ctx context.Context, userDN string) ([]*LDAPGroup, error)

	// Synchronization
	SyncUsers(ctx context.Context, config *SyncConfig) (*SyncResult, error)
	SyncGroups(ctx context.Context, config *SyncConfig) (*SyncResult, error)
	GetSyncStatus(ctx context.Context, syncID string) (*SyncStatus, error)
}

// OpenSearchManager defines OpenSearch operations for Delphi
type OpenSearchManager interface {
	// Cluster operations
	GetClusterHealth(ctx context.Context) (*ClusterHealth, error)
	GetClusterStats(ctx context.Context) (*ClusterStats, error)

	// Index operations
	CreateIndex(ctx context.Context, spec *OpenSearchIndexSpec) (*OpenSearchIndex, error)
	DeleteIndex(ctx context.Context, indexName string) error
	GetIndexHealth(ctx context.Context, indexName string) (*IndexHealth, error)
	ListIndices(ctx context.Context, pattern string) ([]*OpenSearchIndex, error)

	// Template operations
	CreateIndexTemplate(ctx context.Context, template *IndexTemplate) error
	UpdateIndexTemplate(ctx context.Context, templateName string, template *IndexTemplate) error
	DeleteIndexTemplate(ctx context.Context, templateName string) error
	GetIndexTemplate(ctx context.Context, templateName string) (*IndexTemplate, error)

	// Security operations
	CreateRole(ctx context.Context, roleSpec *OpenSearchRoleSpec) (*OpenSearchRole, error)
	UpdateRole(ctx context.Context, roleName string, roleSpec *OpenSearchRoleSpec) error
	DeleteRole(ctx context.Context, roleName string) error
	GetRole(ctx context.Context, roleName string) (*OpenSearchRole, error)

	// Query and search operations
	Search(ctx context.Context, query *SearchQuery) (*SearchResult, error)
	Aggregate(ctx context.Context, query *AggregationQuery) (*AggregationResult, error)
	GetDocumentCount(ctx context.Context, indexName string) (int64, error)
}

// SecurityAnalysisService defines security analysis and threat detection
type SecurityAnalysisService interface {
	// Threat detection
	AnalyzeThreat(ctx context.Context, data *ThreatData) (*ThreatAnalysis, error)
	GetThreatIndicators(ctx context.Context, tenantID string) ([]*ThreatIndicator, error)
	UpdateThreatIntelligence(ctx context.Context, indicators []*ThreatIndicator) error

	// Vulnerability assessment
	ScanForVulnerabilities(ctx context.Context, targetSpec *ScanTarget) (*VulnerabilityScan, error)
	GetVulnerabilityReport(ctx context.Context, scanID string) (*VulnerabilityReport, error)
	GetVulnerabilityTrends(ctx context.Context, tenantID string, timeRange *TimeRange) (*VulnerabilityTrends, error)

	// Incident response
	CreateIncident(ctx context.Context, incidentSpec *IncidentSpec) (*SecurityIncident, error)
	UpdateIncident(ctx context.Context, incidentID string, update *IncidentUpdate) error
	GetIncident(ctx context.Context, incidentID string) (*SecurityIncident, error)
	ListIncidents(ctx context.Context, filter *IncidentFilter) ([]*SecurityIncident, error)

	// Compliance analysis
	RunComplianceCheck(ctx context.Context, tenantID string, framework *ComplianceFramework) (*ComplianceCheckResult, error)
	GetComplianceStatus(ctx context.Context, tenantID string) (*ComplianceStatus, error)
	GenerateComplianceReport(ctx context.Context, tenantID string, spec *ComplianceReportSpec) (*ComplianceReport, error)
}

// AlertingService defines alerting and notification operations
type AlertingService interface {
	// Alert management
	CreateAlert(ctx context.Context, alertSpec *AlertSpec) (*Alert, error)
	UpdateAlert(ctx context.Context, alertID string, update *AlertUpdate) error
	AcknowledgeAlert(ctx context.Context, alertID string, userID string) error
	ResolveAlert(ctx context.Context, alertID string, resolution *AlertResolution) error

	// Alert querying
	GetAlert(ctx context.Context, alertID string) (*Alert, error)
	ListAlerts(ctx context.Context, filter *AlertFilter) ([]*Alert, error)
	GetAlertStatistics(ctx context.Context, tenantID string, timeRange *TimeRange) (*AlertStatistics, error)

	// Notification management
	SendNotification(ctx context.Context, notification *Notification) error
	CreateNotificationRule(ctx context.Context, rule *NotificationRule) error
	UpdateNotificationRule(ctx context.Context, ruleID string, rule *NotificationRule) error
	GetNotificationHistory(ctx context.Context, filter *NotificationFilter) ([]*NotificationHistory, error)

	// Alert rules and correlation
	CreateAlertRule(ctx context.Context, rule *AlertRule) error
	UpdateAlertRule(ctx context.Context, ruleID string, rule *AlertRule) error
	TestAlertRule(ctx context.Context, rule *AlertRule, testData *AlertTestData) (*AlertRuleTestResult, error)
	GetCorrelationRules(ctx context.Context, tenantID string) ([]*CorrelationRule, error)
}

// ConfigurationService defines configuration management operations
type ConfigurationService interface {
	// System configuration
	GetSystemConfig(ctx context.Context) (*SystemConfiguration, error)
	UpdateSystemConfig(ctx context.Context, config *SystemConfiguration) error
	ValidateSystemConfig(ctx context.Context, config *SystemConfiguration) error

	// Tenant configuration
	GetTenantConfig(ctx context.Context, tenantID string) (*TenantConfiguration, error)
	UpdateTenantConfig(ctx context.Context, tenantID string, config *TenantConfiguration) error
	ValidateTenantConfig(ctx context.Context, config *TenantConfiguration) error

	// Agent configuration
	GetAgentConfig(ctx context.Context, agentID string) (*AgentConfiguration, error)
	UpdateAgentConfig(ctx context.Context, agentID string, config *AgentConfiguration) error
	PushAgentConfig(ctx context.Context, agentID string) error

	// Configuration templates
	CreateConfigTemplate(ctx context.Context, template *ConfigTemplate) error
	GetConfigTemplate(ctx context.Context, templateID string) (*ConfigTemplate, error)
	ApplyConfigTemplate(ctx context.Context, templateID string, variables map[string]interface{}) (*Configuration, error)

	// Configuration backup and restore
	BackupConfiguration(ctx context.Context, scope *ConfigBackupScope) (*ConfigBackup, error)
	RestoreConfiguration(ctx context.Context, backupID string) error
	ListConfigBackups(ctx context.Context) ([]*ConfigBackup, error)
}

// Repository interfaces for persistence

// TenantRepository defines tenant persistence operations
type TenantRepository interface {
	SaveTenant(ctx context.Context, tenant *Tenant) error
	GetTenant(ctx context.Context, tenantID string) (*Tenant, error)
	ListTenants(ctx context.Context, filter *TenantFilter) ([]*Tenant, error)
	UpdateTenant(ctx context.Context, tenant *Tenant) error
	DeleteTenant(ctx context.Context, tenantID string) error
	GetTenantByName(ctx context.Context, name string) (*Tenant, error)
}

// UserRepository defines user persistence operations
type UserRepository interface {
	SaveUser(ctx context.Context, user *User) error
	GetUser(ctx context.Context, userID string) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	ListUsers(ctx context.Context, filter *UserFilter) ([]*User, error)
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, userID string) error
	SaveUserSession(ctx context.Context, session *UserSession) error
	GetUserSession(ctx context.Context, sessionID string) (*UserSession, error)
}

// ConfigurationRepository defines configuration persistence operations
type ConfigurationRepository interface {
	SaveConfiguration(ctx context.Context, config *Configuration) error
	GetConfiguration(ctx context.Context, configID string) (*Configuration, error)
	GetConfigurationByType(ctx context.Context, configType ConfigurationType) (*Configuration, error)
	ListConfigurations(ctx context.Context, filter *ConfigurationFilter) ([]*Configuration, error)
	DeleteConfiguration(ctx context.Context, configID string) error
	SaveConfigurationVersion(ctx context.Context, version *ConfigurationVersion) error
	GetConfigurationHistory(ctx context.Context, configID string) ([]*ConfigurationVersion, error)
}

// AlertRepository defines alert persistence operations
type AlertRepository interface {
	SaveAlert(ctx context.Context, alert *Alert) error
	GetAlert(ctx context.Context, alertID string) (*Alert, error)
	ListAlerts(ctx context.Context, filter *AlertFilter) ([]*Alert, error)
	UpdateAlert(ctx context.Context, alert *Alert) error
	DeleteAlert(ctx context.Context, alertID string) error
	GetAlertsByTenant(ctx context.Context, tenantID string, filter *AlertFilter) ([]*Alert, error)
}

// IncidentRepository defines incident persistence operations
type IncidentRepository interface {
	SaveIncident(ctx context.Context, incident *SecurityIncident) error
	GetIncident(ctx context.Context, incidentID string) (*SecurityIncident, error)
	ListIncidents(ctx context.Context, filter *IncidentFilter) ([]*SecurityIncident, error)
	UpdateIncident(ctx context.Context, incident *SecurityIncident) error
	DeleteIncident(ctx context.Context, incidentID string) error
	GetIncidentsByTenant(ctx context.Context, tenantID string) ([]*SecurityIncident, error)
}

// AuditRepository defines audit logging for security operations
type AuditRepository interface {
	RecordSecurityEvent(ctx context.Context, event *SecurityAuditEvent) error
	QuerySecurityEvents(ctx context.Context, filter *SecurityAuditFilter) ([]*SecurityAuditEvent, error)
	GetEventsByTenant(ctx context.Context, tenantID string, filter *SecurityAuditFilter) ([]*SecurityAuditEvent, error)
	GetEventsByUser(ctx context.Context, userID string, filter *SecurityAuditFilter) ([]*SecurityAuditEvent, error)
}

// SecretRepository defines secure credential storage
type SecretRepository interface {
	StoreSecret(ctx context.Context, key string, secret *SecretData) error
	RetrieveSecret(ctx context.Context, key string) (*SecretData, error)
	UpdateSecret(ctx context.Context, key string, secret *SecretData) error
	DeleteSecret(ctx context.Context, key string) error
	ListSecrets(ctx context.Context, prefix string) ([]*SecretMetadata, error)
	RotateSecret(ctx context.Context, key string, generator SecretGenerator) (*SecretData, error)
}

// Validation interfaces

// TenantValidator defines tenant validation operations
type TenantValidator interface {
	ValidateTenantSpec(spec *TenantSpec) error
	ValidateTenantConfiguration(config *TenantConfiguration) error
	ValidateTenantResources(resources *TenantResources) error
	ValidateTenantSecurity(security *TenantSecurity) error
}

// SecurityValidator defines security validation operations
type SecurityValidator interface {
	ValidateSecurityPolicy(policy *SecurityPolicy) error
	ValidateAccessControl(access *AccessControl) error
	ValidateEncryption(encryption *EncryptionConfig) error
	ValidateCompliance(compliance *ComplianceConfig) error
}

// ConfigurationValidator defines configuration validation
type ConfigurationValidator interface {
	ValidateWazuhConfig(config *WazuhConfiguration) error
	ValidateLDAPConfig(config *LDAPConfig) error
	ValidateOpenSearchConfig(config *OpenSearchConfig) error
	ValidateAgentConfig(config *AgentConfiguration) error
}

// Infrastructure interfaces

// HTTPClient defines HTTP client operations for API communication
type HTTPClient interface {
	Get(ctx context.Context, url string, headers map[string]string) (*HTTPResponse, error)
	Post(ctx context.Context, url string, body interface{}, headers map[string]string) (*HTTPResponse, error)
	Put(ctx context.Context, url string, body interface{}, headers map[string]string) (*HTTPResponse, error)
	Delete(ctx context.Context, url string, headers map[string]string) (*HTTPResponse, error)
	Patch(ctx context.Context, url string, body interface{}, headers map[string]string) (*HTTPResponse, error)
}

// AuthenticationProvider defines authentication operations
type AuthenticationProvider interface {
	Authenticate(ctx context.Context, credentials *Credentials) (*AuthToken, error)
	ValidateToken(ctx context.Context, token *AuthToken) error
	RefreshToken(ctx context.Context, token *AuthToken) (*AuthToken, error)
	RevokeToken(ctx context.Context, token *AuthToken) error
}

// PasswordManager defines password operations
type PasswordManager interface {
	GeneratePassword(ctx context.Context, policy *PasswordPolicy) (string, error)
	ValidatePassword(ctx context.Context, password string, policy *PasswordPolicy) error
	HashPassword(ctx context.Context, password string) (string, error)
	VerifyPassword(ctx context.Context, password, hash string) error
	GenerateAPIKey(ctx context.Context) (string, error)
}

// TemplateEngine defines template processing operations
type TemplateEngine interface {
	ProcessTemplate(ctx context.Context, template string, variables map[string]interface{}) (string, error)
	ValidateTemplate(ctx context.Context, template string) error
	GetTemplateVariables(ctx context.Context, template string) ([]string, error)
	RegisterFunction(name string, fn interface{}) error
}

// NotificationProvider defines notification delivery operations
type NotificationProvider interface {
	SendEmail(ctx context.Context, email *EmailNotification) error
	SendSMS(ctx context.Context, sms *SMSNotification) error
	SendSlack(ctx context.Context, slack *SlackNotification) error
	SendWebhook(ctx context.Context, webhook *WebhookNotification) error
	ValidateConfiguration(ctx context.Context, config *NotificationConfig) error
}

// BackupProvider defines backup and restore operations
type BackupProvider interface {
	CreateBackup(ctx context.Context, spec *BackupSpec) (*Backup, error)
	RestoreBackup(ctx context.Context, backupID string, options *RestoreOptions) error
	ListBackups(ctx context.Context, filter *BackupFilter) ([]*Backup, error)
	DeleteBackup(ctx context.Context, backupID string) error
	ValidateBackup(ctx context.Context, backupID string) (*BackupValidation, error)
}

// MonitoringProvider defines monitoring and metrics collection
type MonitoringProvider interface {
	CollectMetrics(ctx context.Context, source string) (*Metrics, error)
	RecordMetric(ctx context.Context, metric *MetricData) error
	QueryMetrics(ctx context.Context, query *MetricQuery) (*MetricResult, error)
	CreateDashboard(ctx context.Context, dashboard *Dashboard) error
	GetSystemHealth(ctx context.Context) (*SystemHealth, error)
}

// Filter and option types

// TenantFilter defines tenant filtering criteria
type TenantFilter struct {
	Names         []string          `json:"names,omitempty"`
	Status        []TenantStatus    `json:"status,omitempty"`
	Environment   []string          `json:"environment,omitempty"`
	CreatedAfter  *time.Time        `json:"created_after,omitempty"`
	CreatedBefore *time.Time        `json:"created_before,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
}

// UserFilter defines user filtering criteria
type UserFilter struct {
	Usernames       []string     `json:"usernames,omitempty"`
	Roles           []string     `json:"roles,omitempty"`
	Status          []UserStatus `json:"status,omitempty"`
	Departments     []string     `json:"departments,omitempty"`
	LastLoginAfter  *time.Time   `json:"last_login_after,omitempty"`
	LastLoginBefore *time.Time   `json:"last_login_before,omitempty"`
}

// AlertFilter defines alert filtering criteria
type AlertFilter struct {
	Severity      []AlertSeverity `json:"severity,omitempty"`
	Status        []AlertStatus   `json:"status,omitempty"`
	Types         []AlertType     `json:"types,omitempty"`
	TenantIDs     []string        `json:"tenant_ids,omitempty"`
	CreatedAfter  *time.Time      `json:"created_after,omitempty"`
	CreatedBefore *time.Time      `json:"created_before,omitempty"`
	Acknowledged  *bool           `json:"acknowledged,omitempty"`
}

// IndexFilter defines index filtering criteria
type IndexFilter struct {
	Names        []string      `json:"names,omitempty"`
	Status       []IndexStatus `json:"status,omitempty"`
	Patterns     []string      `json:"patterns,omitempty"`
	CreatedAfter *time.Time    `json:"created_after,omitempty"`
}

// RoleFilter defines role filtering criteria
type RoleFilter struct {
	Names       []string   `json:"names,omitempty"`
	Types       []RoleType `json:"types,omitempty"`
	Permissions []string   `json:"permissions,omitempty"`
}

// AgentFilter defines agent filtering criteria
type AgentFilter struct {
	Status        []AgentStatus `json:"status,omitempty"`
	Groups        []string      `json:"groups,omitempty"`
	Platforms     []string      `json:"platforms,omitempty"`
	Versions      []string      `json:"versions,omitempty"`
	LastSeenAfter *time.Time    `json:"last_seen_after,omitempty"`
}

// ConfigurationFilter defines configuration filtering criteria
type ConfigurationFilter struct {
	Types         []ConfigurationType   `json:"types,omitempty"`
	Status        []ConfigurationStatus `json:"status,omitempty"`
	CreatedAfter  *time.Time            `json:"created_after,omitempty"`
	CreatedBefore *time.Time            `json:"created_before,omitempty"`
}

// IncidentFilter defines incident filtering criteria
type IncidentFilter struct {
	Severity      []IncidentSeverity `json:"severity,omitempty"`
	Status        []IncidentStatus   `json:"status,omitempty"`
	Types         []IncidentType     `json:"types,omitempty"`
	TenantIDs     []string           `json:"tenant_ids,omitempty"`
	CreatedAfter  *time.Time         `json:"created_after,omitempty"`
	CreatedBefore *time.Time         `json:"created_before,omitempty"`
}

// SecurityAuditFilter defines security audit filtering criteria
type SecurityAuditFilter struct {
	EventTypes []SecurityEventType `json:"event_types,omitempty"`
	Users      []string            `json:"users,omitempty"`
	TenantIDs  []string            `json:"tenant_ids,omitempty"`
	Severity   []EventSeverity     `json:"severity,omitempty"`
	After      *time.Time          `json:"after,omitempty"`
	Before     *time.Time          `json:"before,omitempty"`
	Limit      int                 `json:"limit,omitempty"`
}

// LDAPUserFilter defines LDAP user search criteria
type LDAPUserFilter struct {
	Username   string   `json:"username,omitempty"`
	Email      string   `json:"email,omitempty"`
	Department string   `json:"department,omitempty"`
	Groups     []string `json:"groups,omitempty"`
	BaseDN     string   `json:"base_dn,omitempty"`
	Filter     string   `json:"filter,omitempty"`
}

// LDAPGroupFilter defines LDAP group search criteria
type LDAPGroupFilter struct {
	Name     string `json:"name,omitempty"`
	BaseDN   string `json:"base_dn,omitempty"`
	Filter   string `json:"filter,omitempty"`
	MemberOf string `json:"member_of,omitempty"`
}

// NotificationFilter defines notification filtering criteria
type NotificationFilter struct {
	Types      []NotificationType   `json:"types,omitempty"`
	Status     []NotificationStatus `json:"status,omitempty"`
	Recipients []string             `json:"recipients,omitempty"`
	SentAfter  *time.Time           `json:"sent_after,omitempty"`
	SentBefore *time.Time           `json:"sent_before,omitempty"`
}

// BackupFilter defines backup filtering criteria
type BackupFilter struct {
	Types         []BackupType   `json:"types,omitempty"`
	Status        []BackupStatus `json:"status,omitempty"`
	CreatedAfter  *time.Time     `json:"created_after,omitempty"`
	CreatedBefore *time.Time     `json:"created_before,omitempty"`
}

// TimeRange defines time range for queries and reports
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// Callback and handler types

// SecretGenerator defines secret generation function
type SecretGenerator func(ctx context.Context) (string, error)

// EventHandler defines security event handling function
type EventHandler func(ctx context.Context, event *SecurityEvent) error

// Enumeration types

type TenantStatus string

const (
	TenantStatusPending   TenantStatus = "pending"
	TenantStatusActive    TenantStatus = "active"
	TenantStatusSuspended TenantStatus = "suspended"
	TenantStatusInactive  TenantStatus = "inactive"
	TenantStatusDeleted   TenantStatus = "deleted"
)

type UserStatus string

const (
	UserStatusActive   UserStatus = "active"
	UserStatusInactive UserStatus = "inactive"
	UserStatusLocked   UserStatus = "locked"
	UserStatusPending  UserStatus = "pending"
	UserStatusExpired  UserStatus = "expired"
)

type AlertSeverity string

const (
	AlertSeverityLow      AlertSeverity = "low"
	AlertSeverityMedium   AlertSeverity = "medium"
	AlertSeverityHigh     AlertSeverity = "high"
	AlertSeverityCritical AlertSeverity = "critical"
)

type AlertStatus string

const (
	AlertStatusOpen          AlertStatus = "open"
	AlertStatusAcknowledged  AlertStatus = "acknowledged"
	AlertStatusInProgress    AlertStatus = "in_progress"
	AlertStatusResolved      AlertStatus = "resolved"
	AlertStatusClosed        AlertStatus = "closed"
	AlertStatusFalsePositive AlertStatus = "false_positive"
)

type AlertType string

const (
	AlertTypeSecurityEvent   AlertType = "security_event"
	AlertTypeSystemHealth    AlertType = "system_health"
	AlertTypePerformance     AlertType = "performance"
	AlertTypeCompliance      AlertType = "compliance"
	AlertTypeThreatDetection AlertType = "threat_detection"
)

type IndexStatus string

const (
	IndexStatusOpen   IndexStatus = "open"
	IndexStatusClosed IndexStatus = "closed"
	IndexStatusRed    IndexStatus = "red"
	IndexStatusYellow IndexStatus = "yellow"
	IndexStatusGreen  IndexStatus = "green"
)

type RoleType string

const (
	RoleTypeAdmin    RoleType = "admin"
	RoleTypeAnalyst  RoleType = "analyst"
	RoleTypeOperator RoleType = "operator"
	RoleTypeViewer   RoleType = "viewer"
	RoleTypeCustom   RoleType = "custom"
)

type AgentStatus string

const (
	AgentStatusActive         AgentStatus = "active"
	AgentStatusDisconnected   AgentStatus = "disconnected"
	AgentStatusPending        AgentStatus = "pending"
	AgentStatusNeverConnected AgentStatus = "never_connected"
)

type ConfigurationType string

const (
	ConfigurationTypeSystem     ConfigurationType = "system"
	ConfigurationTypeTenant     ConfigurationType = "tenant"
	ConfigurationTypeAgent      ConfigurationType = "agent"
	ConfigurationTypeLDAP       ConfigurationType = "ldap"
	ConfigurationTypeOpenSearch ConfigurationType = "opensearch"
	ConfigurationTypeWazuh      ConfigurationType = "wazuh"
)

type ConfigurationStatus string

const (
	ConfigurationStatusDraft    ConfigurationStatus = "draft"
	ConfigurationStatusActive   ConfigurationStatus = "active"
	ConfigurationStatusInactive ConfigurationStatus = "inactive"
	ConfigurationStatusArchived ConfigurationStatus = "archived"
)

type IncidentSeverity string

const (
	IncidentSeverityLow      IncidentSeverity = "low"
	IncidentSeverityMedium   IncidentSeverity = "medium"
	IncidentSeverityHigh     IncidentSeverity = "high"
	IncidentSeverityCritical IncidentSeverity = "critical"
)

type IncidentStatus string

const (
	IncidentStatusNew           IncidentStatus = "new"
	IncidentStatusTriaged       IncidentStatus = "triaged"
	IncidentStatusInvestigating IncidentStatus = "investigating"
	IncidentStatusContained     IncidentStatus = "contained"
	IncidentStatusEradicated    IncidentStatus = "eradicated"
	IncidentStatusRecovered     IncidentStatus = "recovered"
	IncidentStatusClosed        IncidentStatus = "closed"
)

type IncidentType string

const (
	IncidentTypeMalware            IncidentType = "malware"
	IncidentTypeIntrusion          IncidentType = "intrusion"
	IncidentTypeDataBreach         IncidentType = "data_breach"
	IncidentTypeDenialOfService    IncidentType = "denial_of_service"
	IncidentTypeUnauthorizedAccess IncidentType = "unauthorized_access"
	IncidentTypePhishing           IncidentType = "phishing"
	IncidentTypeInsiderThreat      IncidentType = "insider_threat"
)

type SecurityEventType string

const (
	SecurityEventTypeLogin           SecurityEventType = "login"
	SecurityEventTypeLogout          SecurityEventType = "logout"
	SecurityEventTypePasswordChange  SecurityEventType = "password_change"
	SecurityEventTypeConfigChange    SecurityEventType = "config_change"
	SecurityEventTypeAlertCreated    SecurityEventType = "alert_created"
	SecurityEventTypeIncidentCreated SecurityEventType = "incident_created"
	SecurityEventTypeTenantCreated   SecurityEventType = "tenant_created"
	SecurityEventTypeUserCreated     SecurityEventType = "user_created"
)

type EventSeverity string

const (
	EventSeverityInfo     EventSeverity = "info"
	EventSeverityWarning  EventSeverity = "warning"
	EventSeverityError    EventSeverity = "error"
	EventSeverityCritical EventSeverity = "critical"
)

type NotificationType string

const (
	NotificationTypeEmail   NotificationType = "email"
	NotificationTypeSMS     NotificationType = "sms"
	NotificationTypeSlack   NotificationType = "slack"
	NotificationTypeWebhook NotificationType = "webhook"
)

type NotificationStatus string

const (
	NotificationStatusPending  NotificationStatus = "pending"
	NotificationStatusSent     NotificationStatus = "sent"
	NotificationStatusFailed   NotificationStatus = "failed"
	NotificationStatusRetrying NotificationStatus = "retrying"
)

type BackupType string

const (
	BackupTypeConfiguration BackupType = "configuration"
	BackupTypeData          BackupType = "data"
	BackupTypeFull          BackupType = "full"
	BackupTypeIncremental   BackupType = "incremental"
)

type BackupStatus string

const (
	BackupStatusPending   BackupStatus = "pending"
	BackupStatusRunning   BackupStatus = "running"
	BackupStatusCompleted BackupStatus = "completed"
	BackupStatusFailed    BackupStatus = "failed"
	BackupStatusCancelled BackupStatus = "cancelled"
)

package temporal

import (
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
)

// ReconciliationRequest represents a request for state reconciliation
type ReconciliationRequest struct {
	Component             string   `json:"component"`
	DryRun                bool     `json:"dry_run"`
	Source                string   `json:"source"` // "git" or "consul"
	GitRepository         string   `json:"git_repository,omitempty"`
	GitBranch             string   `json:"git_branch,omitempty"`
	GitPath               string   `json:"git_path,omitempty"`
	CaddyAdminEndpoints   []string `json:"caddy_admin_endpoints,omitempty"`
	AuthentikURL          string   `json:"authentik_url,omitempty"`
	AuthentikToken        string   `json:"authentik_token,omitempty"`
	Force                 bool     `json:"force"`
}

// ReconciliationState tracks the progress of a reconciliation workflow
type ReconciliationState struct {
	ID                string                   `json:"id"`
	StartTime         time.Time                `json:"start_time"`
	CompletedAt       time.Time                `json:"completed_at,omitempty"`
	Component         string                   `json:"component"`
	DesiredItemCount  int                      `json:"desired_item_count"`
	RuntimeItemCount  int                      `json:"runtime_item_count"`
	ToCreate          int                      `json:"to_create"`
	ToUpdate          int                      `json:"to_update"`
	ToDelete          int                      `json:"to_delete"`
	Success           bool                     `json:"success"`
	DryRun            bool                     `json:"dry_run"`
	ChangeReport      ChangeReport             `json:"change_report,omitempty"`
	Error             string                   `json:"error,omitempty"`
}

// DesiredState represents the desired configuration state
type DesiredState struct {
	Routes       []*hecate.Route      `json:"routes"`
	Upstreams    []*hecate.Upstream   `json:"upstreams"`
	AuthPolicies []*hecate.AuthPolicy `json:"auth_policies"`
	Version      string               `json:"version"`
	Source       string               `json:"source"`
}

// RuntimeState represents the current runtime state
type RuntimeState struct {
	Routes       []*hecate.Route      `json:"routes"`
	Upstreams    []*hecate.Upstream   `json:"upstreams"`
	AuthPolicies []*hecate.AuthPolicy `json:"auth_policies"`
	Timestamp    time.Time            `json:"timestamp"`
}

// StateDiff represents differences between desired and runtime state
type StateDiff struct {
	ToCreate []StateChange `json:"to_create"`
	ToUpdate []StateChange `json:"to_update"`
	ToDelete []StateChange `json:"to_delete"`
}

// StateChange represents a single state change
type StateChange struct {
	Type        string      `json:"type"`        // "route", "upstream", "auth_policy"
	Name        string      `json:"name"`
	Action      string      `json:"action"`      // "create", "update", "delete"
	OldValue    interface{} `json:"old_value,omitempty"`
	NewValue    interface{} `json:"new_value,omitempty"`
	Dependencies []string   `json:"dependencies,omitempty"`
}

// ChangeReport provides a summary of changes to be made
type ChangeReport struct {
	Summary     string        `json:"summary"`
	Changes     []StateChange `json:"changes"`
	Impact      string        `json:"impact"`
	Risks       []string      `json:"risks"`
	Rollback    string        `json:"rollback"`
	GeneratedAt time.Time     `json:"generated_at"`
}

// RouteCreationRequest represents a request to create a new route
type RouteCreationRequest struct {
	Domain              string            `json:"domain"`
	Upstreams           []string          `json:"upstreams"`
	AuthPolicy          string            `json:"auth_policy,omitempty"`
	Headers             map[string]string `json:"headers,omitempty"`
	Middleware          []string          `json:"middleware,omitempty"`
	ManageDNS           bool              `json:"manage_dns"`
	DNSTarget           string            `json:"dns_target,omitempty"`
	DNSTTL              int               `json:"dns_ttl,omitempty"`
	EnableSSL           bool              `json:"enable_ssl"`
	CertificateProvider string            `json:"certificate_provider,omitempty"`
	CertificateEmail    string            `json:"certificate_email,omitempty"`
	EnableMonitoring    bool              `json:"enable_monitoring"`
	HealthCheckPath     string            `json:"health_check_path,omitempty"`
	NotificationEmail   string            `json:"notification_email,omitempty"`
}

// RouteCreationState tracks the progress of route creation
type RouteCreationState struct {
	Domain              string    `json:"domain"`
	StartTime           time.Time `json:"start_time"`
	CompletedAt         time.Time `json:"completed_at,omitempty"`
	DNSCreated          bool      `json:"dns_created"`
	CertificateCreated  bool      `json:"certificate_created"`
	CertificateID       string    `json:"certificate_id,omitempty"`
	AuthConfigured      bool      `json:"auth_configured"`
	RouteCreated        bool      `json:"route_created"`
	MonitoringConfigured bool     `json:"monitoring_configured"`
	Success             bool      `json:"success"`
	Error               string    `json:"error,omitempty"`
}

// RouteValidation represents route validation results
type RouteValidation struct {
	Valid              bool   `json:"valid"`
	Reason             string `json:"reason,omitempty"`
	HasValidCertificate bool  `json:"has_valid_certificate"`
}

// DNSStatus represents DNS record status
type DNSStatus struct {
	Exists        bool   `json:"exists"`
	CorrectTarget bool   `json:"correct_target"`
	CurrentValue  string `json:"current_value,omitempty"`
}

// DNSCheckRequest represents a DNS check request
type DNSCheckRequest struct {
	Domain         string `json:"domain"`
	ExpectedTarget string `json:"expected_target"`
}

// DNSRecordRequest represents a DNS record creation request
type DNSRecordRequest struct {
	Domain string `json:"domain"`
	Type   string `json:"type"`
	Value  string `json:"value"`
	TTL    int    `json:"ttl"`
}

// DNSPropagationRequest represents a DNS propagation check request
type DNSPropagationRequest struct {
	Domain        string `json:"domain"`
	ExpectedValue string `json:"expected_value"`
}

// Certificate represents an SSL certificate
type Certificate struct {
	ID        string    `json:"id"`
	Domain    string    `json:"domain"`
	Provider  string    `json:"provider"`
	ExpiresAt time.Time `json:"expires_at"`
	Status    string    `json:"status"`
}

// CertificateRequest represents a certificate request
type CertificateRequest struct {
	Domain   string `json:"domain"`
	Provider string `json:"provider"`
	Email    string `json:"email"`
}

// RouteAuthConfig represents route authentication configuration
type RouteAuthConfig struct {
	Domain     string `json:"domain"`
	PolicyName string `json:"policy_name"`
}

// MonitoringConfig represents monitoring configuration
type MonitoringConfig struct {
	Domain            string `json:"domain"`
	HealthCheckPath   string `json:"health_check_path"`
	NotificationEmail string `json:"notification_email"`
}

// SecretRotationRequest represents a secret rotation request
type SecretRotationRequest struct {
	SecretType      string `json:"secret_type"`
	Strategy        string `json:"strategy"` // "dual-secret" or "immediate"
	ContinueOnError bool   `json:"continue_on_error"`
}

// SecretRotationState tracks secret rotation progress
type SecretRotationState struct {
	SecretType    string    `json:"secret_type"`
	Strategy      string    `json:"strategy"`
	StartTime     time.Time `json:"start_time"`
	CompletedAt   time.Time `json:"completed_at,omitempty"`
	CurrentPhase  string    `json:"current_phase"`
	Success       bool      `json:"success"`
	Error         string    `json:"error,omitempty"`
}

// DistributedLock represents a distributed lock
type DistributedLock struct {
	Key       string    `json:"key"`
	Owner     string    `json:"owner"`
	TTL       time.Duration `json:"ttl"`
	AcquiredAt time.Time `json:"acquired_at"`
}

// LockRequest represents a lock acquisition request
type LockRequest struct {
	Key   string        `json:"key"`
	TTL   time.Duration `json:"ttl"`
	Owner string        `json:"owner"`
}

// GitStateRequest represents a Git state fetch request
type GitStateRequest struct {
	Repository string `json:"repository"`
	Branch     string `json:"branch"`
	Path       string `json:"path"`
	Component  string `json:"component"`
}

// ConsulStateRequest represents a Consul state fetch request
type ConsulStateRequest struct {
	Prefix    string `json:"prefix"`
	Component string `json:"component"`
}

// CaddyStateRequest represents a Caddy state fetch request
type CaddyStateRequest struct {
	AdminEndpoints []string `json:"admin_endpoints"`
}

// AuthentikStateRequest represents an Authentik state fetch request
type AuthentikStateRequest struct {
	BaseURL string `json:"base_url"`
	Token   string `json:"token"`
}

// DiffRequest represents a state diff calculation request
type DiffRequest struct {
	Desired DesiredState `json:"desired"`
	Runtime RuntimeState `json:"runtime"`
}

// ConsulRouteConfig represents route configuration stored in Consul
type ConsulRouteConfig struct {
	Key   string        `json:"key"`
	Route hecate.Route  `json:"route"`
}

// AlertRequest represents an alert request
type AlertRequest struct {
	Title    string `json:"title"`
	Message  string `json:"message"`
	Severity string `json:"severity"`
}

// RouteUpdateRequest represents a route update request
type RouteUpdateRequest struct {
	Domain  string                 `json:"domain"`
	Updates map[string]interface{} `json:"updates"`
}

// RouteDeleteRequest represents a route deletion request
type RouteDeleteRequest struct {
	Domain            string `json:"domain"`
	DeleteDNS         bool   `json:"delete_dns"`
	DeleteCertificate bool   `json:"delete_certificate"`
}
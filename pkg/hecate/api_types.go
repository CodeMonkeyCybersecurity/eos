// pkg/hecate/api_types.go
package hecate

import (
	"time"
)

// CreateRouteRequest represents a request to create a new route
type CreateRouteRequest struct {
	Domain              string            `json:"domain" validate:"required,fqdn"`
	Upstreams           []string          `json:"upstreams" validate:"required,min=1"`
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

// CreateRouteResponse represents the response after creating a route
type CreateRouteResponse struct {
	ID         string    `json:"id"`
	Domain     string    `json:"domain"`
	WorkflowID string    `json:"workflow_id"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
}

// UpdateRouteRequest represents a request to update an existing route
type UpdateRouteRequest struct {
	Domain      string            `json:"domain"`
	Upstreams   []string          `json:"upstreams,omitempty"`
	AuthPolicy  string            `json:"auth_policy,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Middleware  []string          `json:"middleware,omitempty"`
	EnableSSL   bool              `json:"enable_ssl,omitempty"`
	WorkflowID  string            `json:"workflow_id,omitempty"`
}

// UpdateRouteResponse represents the response after updating a route
type UpdateRouteResponse struct {
	Domain     string    `json:"domain"`
	WorkflowID string    `json:"workflow_id"`
	Status     string    `json:"status"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// DeleteRouteRequest represents a request to delete a route
type DeleteRouteRequest struct {
	Domain     string `json:"domain" validate:"required"`
	Force      bool   `json:"force"`
	WorkflowID string `json:"workflow_id,omitempty"`
}

// DeleteRouteResponse represents the response after deleting a route
type DeleteRouteResponse struct {
	Domain     string    `json:"domain"`
	WorkflowID string    `json:"workflow_id"`
	Status     string    `json:"status"`
	DeletedAt  time.Time `json:"deleted_at"`
}

// CreateAuthPolicyRequest represents a request to create an auth policy
type CreateAuthPolicyRequest struct {
	Name       string            `json:"name" validate:"required"`
	Provider   string            `json:"provider" validate:"required"`
	Flow       string            `json:"flow,omitempty"`
	Groups     []string          `json:"groups,omitempty"`
	RequireMFA bool              `json:"require_mfa"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// CreateAuthPolicyResponse represents the response after creating an auth policy
type CreateAuthPolicyResponse struct {
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// ReconcileStateRequest represents a request to reconcile state
type ReconcileStateRequest struct {
	Component string `json:"component" validate:"required"`
	DryRun    bool   `json:"dry_run"`
	Source    string `json:"source"`
	Force     bool   `json:"force"`
}

// ReconcileStateResponse represents the response after state reconciliation
type ReconcileStateResponse struct {
	Component   string                 `json:"component"`
	Status      string                 `json:"status"`
	Changes     []ReconciliationChange `json:"changes"`
	WorkflowID  string                 `json:"workflow_id"`
	StartedAt   time.Time              `json:"started_at"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
}

// ReconciliationChange represents a change made during reconciliation
type ReconciliationChange struct {
	Type        string      `json:"type"`
	Resource    string      `json:"resource"`
	Action      string      `json:"action"`
	OldValue    interface{} `json:"old_value,omitempty"`
	NewValue    interface{} `json:"new_value,omitempty"`
	Description string      `json:"description"`
}

// RotateSecretsRequest represents a request to rotate secrets
type RotateSecretsRequest struct {
	SecretType       string `json:"secret_type" validate:"required"`
	Strategy         string `json:"strategy" validate:"required"`
	ContinueOnError  bool   `json:"continue_on_error"`
	NotificationURL  string `json:"notification_url,omitempty"`
}

// RotateSecretsResponse represents the response after secret rotation
type RotateSecretsResponse struct {
	SecretType      string    `json:"secret_type"`
	Strategy        string    `json:"strategy"`
	WorkflowID      string    `json:"workflow_id"`
	Status          string    `json:"status"`
	RotatedSecrets  []string  `json:"rotated_secrets"`
	FailedSecrets   []string  `json:"failed_secrets"`
	StartedAt       time.Time `json:"started_at"`
	CompletedAt     *time.Time `json:"completed_at,omitempty"`
}

// ListRoutesRequest represents a request to list routes
type ListRoutesRequest struct {
	Domain     string `json:"domain,omitempty"`
	AuthPolicy string `json:"auth_policy,omitempty"`
	Status     string `json:"status,omitempty"`
	Limit      int    `json:"limit,omitempty"`
	Offset     int    `json:"offset,omitempty"`
}

// ListRoutesResponse represents the response with route list
type ListRoutesResponse struct {
	Routes []RouteListItem `json:"routes"`
	Total  int             `json:"total"`
	Limit  int             `json:"limit"`
	Offset int             `json:"offset"`
}

// RouteListItem represents a route in the list
type RouteListItem struct {
	Domain      string            `json:"domain"`
	Upstream    string            `json:"upstream"`
	AuthPolicy  string            `json:"auth_policy,omitempty"`
	Status      string            `json:"status"`
	TLSEnabled  bool              `json:"tls_enabled"`
	DNSManaged  bool              `json:"dns_managed"`
	Monitoring  bool              `json:"monitoring"`
	Headers     map[string]string `json:"headers,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// ListAuthPoliciesResponse represents the response with auth policy list
type ListAuthPoliciesResponse struct {
	Policies []AuthPolicyListItem `json:"policies"`
	Total    int                  `json:"total"`
}

// AuthPolicyListItem represents an auth policy in the list
type AuthPolicyListItem struct {
	Name       string            `json:"name"`
	Provider   string            `json:"provider"`
	Flow       string            `json:"flow"`
	Groups     []string          `json:"groups,omitempty"`
	RequireMFA bool              `json:"require_mfa"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

// StatusResponse represents the status of Hecate components
type StatusResponse struct {
	Overall    string                    `json:"overall"`
	Components map[string]ComponentStatus `json:"components"`
	Timestamp  time.Time                 `json:"timestamp"`
}

// ComponentStatus represents the status of a single component
type ComponentStatus struct {
	Status      string                 `json:"status"`
	Healthy     bool                   `json:"healthy"`
	Version     string                 `json:"version,omitempty"`
	LastCheck   time.Time              `json:"last_check"`
	Details     map[string]interface{} `json:"details,omitempty"`
	ErrorMessage string                `json:"error_message,omitempty"`
}

// ErrorResponse represents an API error response
type ErrorResponse struct {
	Error   string                 `json:"error"`
	Code    string                 `json:"code,omitempty"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// WorkflowStatusResponse represents the status of a workflow
type WorkflowStatusResponse struct {
	WorkflowID   string                 `json:"workflow_id"`
	Status       string                 `json:"status"`
	Result       interface{}            `json:"result,omitempty"`
	Error        string                 `json:"error,omitempty"`
	StartedAt    time.Time              `json:"started_at"`
	CompletedAt  *time.Time             `json:"completed_at,omitempty"`
	Progress     *WorkflowProgress      `json:"progress,omitempty"`
	History      []WorkflowHistoryEvent `json:"history,omitempty"`
}

// WorkflowProgress represents the progress of a workflow
type WorkflowProgress struct {
	CurrentStep   string  `json:"current_step"`
	TotalSteps    int     `json:"total_steps"`
	CompletedSteps int    `json:"completed_steps"`
	Percentage    float64 `json:"percentage"`
}

// WorkflowHistoryEvent represents an event in workflow history
type WorkflowHistoryEvent struct {
	Timestamp   time.Time   `json:"timestamp"`
	EventType   string      `json:"event_type"`
	Description string      `json:"description"`
	Data        interface{} `json:"data,omitempty"`
}
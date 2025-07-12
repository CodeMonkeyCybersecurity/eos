package api

import (
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
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

// Validate validates the create route request
func (req *CreateRouteRequest) Validate() error {
	if req.Domain == "" {
		return NewValidationError("domain", "domain is required")
	}
	if len(req.Upstreams) == 0 {
		return NewValidationError("upstreams", "at least one upstream is required")
	}
	if req.ManageDNS && req.DNSTarget == "" {
		return NewValidationError("dns_target", "dns_target is required when manage_dns is true")
	}
	if req.EnableSSL && req.CertificateEmail == "" {
		return NewValidationError("certificate_email", "certificate_email is required when enable_ssl is true")
	}
	return nil
}

// CreateRouteResponse represents the response from creating a route
type CreateRouteResponse struct {
	ID         string    `json:"id"`
	Domain     string    `json:"domain"`
	WorkflowID string    `json:"workflow_id"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
}

// UpdateRouteRequest represents a request to update a route
type UpdateRouteRequest struct {
	Updates map[string]interface{} `json:"updates" validate:"required"`
}

// UpdateRouteResponse represents the response from updating a route
type UpdateRouteResponse struct {
	ID         string    `json:"id"`
	Domain     string    `json:"domain"`
	WorkflowID string    `json:"workflow_id"`
	Status     string    `json:"status"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// DeleteRouteResponse represents the response from deleting a route
type DeleteRouteResponse struct {
	ID         string    `json:"id"`
	Domain     string    `json:"domain"`
	WorkflowID string    `json:"workflow_id"`
	Status     string    `json:"status"`
	DeletedAt  time.Time `json:"deleted_at"`
}

// RouteResponse represents a route in API responses
type RouteResponse struct {
	ID          string                 `json:"id"`
	Domain      string                 `json:"domain"`
	Upstreams   []string               `json:"upstreams"`
	AuthPolicy  string                 `json:"auth_policy,omitempty"`
	Headers     map[string]string      `json:"headers,omitempty"`
	Middleware  []string               `json:"middleware,omitempty"`
	Status      string                 `json:"status"`
	Health      *RouteHealthResponse   `json:"health,omitempty"`
	Certificate *CertificateResponse   `json:"certificate,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// RouteHealthResponse represents route health status
type RouteHealthResponse struct {
	Status       string        `json:"status"`
	ResponseTime time.Duration `json:"response_time"`
	LastCheck    time.Time     `json:"last_check"`
	ErrorMessage string        `json:"error_message,omitempty"`
}

// CertificateResponse represents certificate information
type CertificateResponse struct {
	ID        string    `json:"id"`
	Domain    string    `json:"domain"`
	Provider  string    `json:"provider"`
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expires_at"`
	IssuedAt  time.Time `json:"issued_at"`
}

// ListRoutesRequest represents a request to list routes
type ListRoutesRequest struct {
	Limit      int    `json:"limit,omitempty"`
	Offset     int    `json:"offset,omitempty"`
	Domain     string `json:"domain,omitempty"`
	Status     string `json:"status,omitempty"`
	AuthPolicy string `json:"auth_policy,omitempty"`
}

// ListRoutesResponse represents the response from listing routes
type ListRoutesResponse struct {
	Routes []RouteResponse `json:"routes"`
	Total  int             `json:"total"`
	Limit  int             `json:"limit"`
	Offset int             `json:"offset"`
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

// Validate validates the create auth policy request
func (req *CreateAuthPolicyRequest) Validate() error {
	if req.Name == "" {
		return NewValidationError("name", "name is required")
	}
	if req.Provider == "" {
		return NewValidationError("provider", "provider is required")
	}
	return nil
}

// CreateAuthPolicyResponse represents the response from creating an auth policy
type CreateAuthPolicyResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Provider  string    `json:"provider"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// AuthPolicyResponse represents an auth policy in API responses
type AuthPolicyResponse struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Provider   string            `json:"provider"`
	Flow       string            `json:"flow,omitempty"`
	Groups     []string          `json:"groups,omitempty"`
	RequireMFA bool              `json:"require_mfa"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	Status     string            `json:"status"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

// ReconcileStateRequest represents a request to reconcile state
type ReconcileStateRequest struct {
	Component string `json:"component" validate:"required"`
	DryRun    bool   `json:"dry_run"`
	Source    string `json:"source"`
	Force     bool   `json:"force"`
}

// Validate validates the reconcile state request
func (req *ReconcileStateRequest) Validate() error {
	if req.Component == "" {
		return NewValidationError("component", "component is required")
	}
	validComponents := []string{"all", "routes", "auth", "upstreams"}
	valid := false
	for _, component := range validComponents {
		if req.Component == component {
			valid = true
			break
		}
	}
	if !valid {
		return NewValidationError("component", "invalid component")
	}
	return nil
}

// ReconcileStateResponse represents the response from state reconciliation
type ReconcileStateResponse struct {
	ID         string              `json:"id"`
	Component  string              `json:"component"`
	Status     string              `json:"status"`
	DryRun     bool                `json:"dry_run"`
	Changes    *ReconcileChanges   `json:"changes,omitempty"`
	WorkflowID string              `json:"workflow_id"`
	StartedAt  time.Time           `json:"started_at"`
}

// ReconcileChanges represents changes from reconciliation
type ReconcileChanges struct {
	ToCreate int                    `json:"to_create"`
	ToUpdate int                    `json:"to_update"`
	ToDelete int                    `json:"to_delete"`
	Details  []ReconcileChangeDetail `json:"details,omitempty"`
}

// ReconcileChangeDetail represents a detailed change
type ReconcileChangeDetail struct {
	Type     string      `json:"type"`
	Name     string      `json:"name"`
	Action   string      `json:"action"`
	OldValue interface{} `json:"old_value,omitempty"`
	NewValue interface{} `json:"new_value,omitempty"`
}

// RotateSecretsRequest represents a request to rotate secrets
type RotateSecretsRequest struct {
	SecretType string `json:"secret_type" validate:"required"`
	Strategy   string `json:"strategy" validate:"required"`
}

// Validate validates the rotate secrets request
func (req *RotateSecretsRequest) Validate() error {
	if req.SecretType == "" {
		return NewValidationError("secret_type", "secret_type is required")
	}
	if req.Strategy == "" {
		return NewValidationError("strategy", "strategy is required")
	}
	validStrategies := []string{"dual-secret", "immediate"}
	valid := false
	for _, strategy := range validStrategies {
		if req.Strategy == strategy {
			valid = true
			break
		}
	}
	if !valid {
		return NewValidationError("strategy", "invalid strategy")
	}
	return nil
}

// RotateSecretsResponse represents the response from secret rotation
type RotateSecretsResponse struct {
	ID         string    `json:"id"`
	SecretType string    `json:"secret_type"`
	Strategy   string    `json:"strategy"`
	Status     string    `json:"status"`
	WorkflowID string    `json:"workflow_id"`
	StartedAt  time.Time `json:"started_at"`
}

// HealthCheckResponse represents system health status
type HealthCheckResponse struct {
	Status    string                 `json:"status"`
	Timestamp time.Time              `json:"timestamp"`
	Version   string                 `json:"version"`
	Services  map[string]ServiceHealth `json:"services"`
}

// ServiceHealth represents individual service health
type ServiceHealth struct {
	Status       string        `json:"status"`
	ResponseTime time.Duration `json:"response_time"`
	LastCheck    time.Time     `json:"last_check"`
	ErrorMessage string        `json:"error_message,omitempty"`
}

// MetricsResponse represents metrics data
type MetricsResponse struct {
	Timestamp time.Time              `json:"timestamp"`
	Routes    map[string]RouteMetrics `json:"routes"`
	System    SystemMetrics          `json:"system"`
}

// RouteMetrics represents metrics for a specific route
type RouteMetrics struct {
	RequestCount   int64         `json:"request_count"`
	ResponseTime   time.Duration `json:"response_time"`
	ErrorRate      float64       `json:"error_rate"`
	BytesIn        int64         `json:"bytes_in"`
	BytesOut       int64         `json:"bytes_out"`
	ActiveRequests int64         `json:"active_requests"`
}

// SystemMetrics represents system-wide metrics
type SystemMetrics struct {
	TotalRoutes       int     `json:"total_routes"`
	HealthyRoutes     int     `json:"healthy_routes"`
	UnhealthyRoutes   int     `json:"unhealthy_routes"`
	TotalRequests     int64   `json:"total_requests"`
	AverageResponseTime time.Duration `json:"average_response_time"`
	SystemLoad        float64 `json:"system_load"`
	MemoryUsage       float64 `json:"memory_usage"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string                 `json:"error"`
	Code    string                 `json:"code,omitempty"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// Error implements the error interface
func (e *ValidationError) Error() string {
	return e.Message
}

// NewValidationError creates a new validation error
func NewValidationError(field, message string) *ValidationError {
	return &ValidationError{
		Field:   field,
		Message: message,
	}
}

// WorkflowStatusResponse represents workflow status
type WorkflowStatusResponse struct {
	ID          string                 `json:"id"`
	Status      string                 `json:"status"`
	StartedAt   time.Time              `json:"started_at"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Progress    float64                `json:"progress"`
	CurrentStep string                 `json:"current_step,omitempty"`
	Error       string                 `json:"error,omitempty"`
	Result      map[string]interface{} `json:"result,omitempty"`
}

// ConvertFromHecateRoute converts a hecate.Route to RouteResponse
func ConvertFromHecateRoute(route *hecate.Route) RouteResponse {
	return RouteResponse{
		ID:         route.Domain, // Use domain as ID for now
		Domain:     route.Domain,
		Upstreams:  []string{route.Upstream},
		AuthPolicy: route.AuthPolicy,
		Headers:    route.Headers,
		Middleware: route.Middleware,
		Status:     "active",
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
}

// ConvertFromHecateAuthPolicy converts a hecate.AuthPolicy to AuthPolicyResponse
func ConvertFromHecateAuthPolicy(policy *hecate.AuthPolicy) AuthPolicyResponse {
	return AuthPolicyResponse{
		ID:         policy.Name,
		Name:       policy.Name,
		Provider:   policy.Provider,
		Flow:       policy.Flow,
		Groups:     policy.Groups,
		RequireMFA: policy.RequireMFA,
		Metadata:   policy.Metadata,
		Status:     "active",
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
}

// ConvertToHecateRoute converts a CreateRouteRequest to hecate.Route
func ConvertToHecateRoute(req CreateRouteRequest) *hecate.Route {
	route := &hecate.Route{
		Domain:     req.Domain,
		AuthPolicy: req.AuthPolicy,
		Headers:    req.Headers,
		Middleware: req.Middleware,
	}

	if len(req.Upstreams) > 0 {
		route.Upstream = req.Upstreams[0]
	}

	if req.HealthCheckPath != "" {
		route.HealthCheck = &hecate.HealthCheck{
			Path:               req.HealthCheckPath,
			Interval:           30 * time.Second,
			Timeout:            5 * time.Second,
			UnhealthyThreshold: 3,
			HealthyThreshold:   2,
		}
	}

	if req.EnableSSL {
		route.TLS = &hecate.TLSConfig{
			AutoHTTPS:  true,
			ForceHTTPS: true,
		}
	}

	return route
}

// ConvertToHecateAuthPolicy converts a CreateAuthPolicyRequest to hecate.AuthPolicy
func ConvertToHecateAuthPolicy(req CreateAuthPolicyRequest) *hecate.AuthPolicy {
	return &hecate.AuthPolicy{
		Name:       req.Name,
		Provider:   req.Provider,
		Flow:       req.Flow,
		Groups:     req.Groups,
		RequireMFA: req.RequireMFA,
		Metadata:   req.Metadata,
	}
}
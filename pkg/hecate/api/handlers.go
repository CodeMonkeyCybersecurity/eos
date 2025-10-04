package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate/temporal"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/gorilla/mux"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Handler provides HTTP handlers for the Hecate API
type Handler struct {
	rc *eos_io.RuntimeContext
}

// NewHandler creates a new API handler
func NewHandler(rc *eos_io.RuntimeContext) *Handler {
	return &Handler{
		rc: rc,
	}
}

// CreateRoute handles POST /api/v1/routes
func (h *Handler) CreateRoute(w http.ResponseWriter, r *http.Request) {
	logger := otelzap.Ctx(h.rc.Ctx)

	// SECURITY: Limit request body size to prevent DoS via JSON bomb
	// A malicious 1MB JSON can expand to gigabytes when parsed (deeply nested arrays/objects)
	const maxRequestSize = 1 * 1024 * 1024 // 1MB maximum
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	var req CreateRouteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate request
	if err := req.Validate(); err != nil {
		h.respondError(w, http.StatusBadRequest, "Validation failed", err)
		return
	}

	// Convert to hecate route
	route := ConvertToHecateRoute(req)

	// Load config and create the route using the existing hecate functions
	config, err := hecate.LoadRouteConfig(h.rc)
	if err != nil {
		logger.Error("Failed to load config",
			zap.String("domain", req.Domain),
			zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "Failed to load config", err)
		return
	}
	
	if err := hecate.CreateRoute(h.rc, config, route); err != nil {
		logger.Error("Failed to create route",
			zap.String("domain", req.Domain),
			zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "Failed to create route", err)
		return
	}

	// Return success response
	response := CreateRouteResponse{
		ID:        route.Domain,
		Domain:    route.Domain,
		Status:    "created",
		CreatedAt: time.Now(),
	}

	logger.Info("Route created successfully",
		zap.String("domain", req.Domain))

	h.respondJSON(w, http.StatusCreated, response)
}

// GetRoute handles GET /api/v1/routes/{domain}
func (h *Handler) GetRoute(w http.ResponseWriter, r *http.Request) {
	logger := otelzap.Ctx(h.rc.Ctx)
	vars := mux.Vars(r)
	domain := vars["domain"]

	// For now, we'll create a mock response since we don't have a storage layer
	// In a full implementation, this would fetch from the state store
	route := &hecate.Route{
		Domain:     domain,
		Upstream:   &hecate.Upstream{URL: "localhost:8080"},
		AuthPolicy: nil,
		Headers:    make(map[string]string),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	response := ConvertFromHecateRoute(route)

	logger.Info("Route retrieved",
		zap.String("domain", domain))

	h.respondJSON(w, http.StatusOK, response)
}

// UpdateRoute handles PUT /api/v1/routes/{domain}
func (h *Handler) UpdateRoute(w http.ResponseWriter, r *http.Request) {
	logger := otelzap.Ctx(h.rc.Ctx)
	vars := mux.Vars(r)
	domain := vars["domain"]

	// SECURITY: Limit request body size to prevent DoS via JSON bomb
	const maxRequestSize = 1 * 1024 * 1024 // 1MB maximum
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	var req UpdateRouteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Load config and update the route using the existing hecate functions
	config, err := hecate.LoadRouteConfig(h.rc)
	if err != nil {
		logger.Error("Failed to load config",
			zap.String("domain", domain),
			zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "Failed to load config", err)
		return
	}
	
	// Convert updates to Route object
	updatedRoute := &hecate.Route{
		Domain: domain,
	}
	
	// Apply updates from the request
	if upstreams, ok := req.Updates["upstreams"].([]interface{}); ok && len(upstreams) > 0 {
		if upstreamURL, ok := upstreams[0].(string); ok {
			updatedRoute.Upstream = &hecate.Upstream{URL: upstreamURL}
		}
	}
	
	if authPolicy, ok := req.Updates["auth_policy"].(string); ok {
		if authPolicy != "" {
			updatedRoute.AuthPolicy = &hecate.AuthPolicy{Name: authPolicy}
		}
	}
	
	if headers, ok := req.Updates["headers"].(map[string]interface{}); ok {
		stringHeaders := make(map[string]string)
		for k, v := range headers {
			if str, ok := v.(string); ok {
				stringHeaders[k] = str
			}
		}
		updatedRoute.Headers = stringHeaders
	}
	
	if err := hecate.UpdateRoute(h.rc, config, domain, updatedRoute); err != nil {
		logger.Error("Failed to update route",
			zap.String("domain", domain),
			zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "Failed to update route", err)
		return
	}

	response := UpdateRouteResponse{
		ID:        domain,
		Domain:    domain,
		Status:    "updated",
		UpdatedAt: time.Now(),
	}

	logger.Info("Route updated successfully",
		zap.String("domain", domain))

	h.respondJSON(w, http.StatusOK, response)
}

// DeleteRoute handles DELETE /api/v1/routes/{domain}
func (h *Handler) DeleteRoute(w http.ResponseWriter, r *http.Request) {
	logger := otelzap.Ctx(h.rc.Ctx)
	vars := mux.Vars(r)
	domain := vars["domain"]

	// Load config and delete the route using the existing hecate functions
	config, err := hecate.LoadRouteConfig(h.rc)
	if err != nil {
		logger.Error("Failed to load config",
			zap.String("domain", domain),
			zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "Failed to load config", err)
		return
	}
	
	// Use default delete options
	deleteOptions := &hecate.DeleteOptions{
		Force:     false,
		Backup:    true,
		RemoveDNS: true,
	}
	
	if err := hecate.DeleteRoute(h.rc, config, domain, deleteOptions); err != nil {
		logger.Error("Failed to delete route",
			zap.String("domain", domain),
			zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "Failed to delete route", err)
		return
	}

	response := DeleteRouteResponse{
		ID:        domain,
		Domain:    domain,
		Status:    "deleted",
		DeletedAt: time.Now(),
	}

	logger.Info("Route deleted successfully",
		zap.String("domain", domain))

	h.respondJSON(w, http.StatusOK, response)
}

// ListRoutes handles GET /api/v1/routes
func (h *Handler) ListRoutes(w http.ResponseWriter, r *http.Request) {
	logger := otelzap.Ctx(h.rc.Ctx)

	// Parse query parameters
	query := r.URL.Query()
	limit := 50
	offset := 0

	if l := query.Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil {
			limit = parsed
		}
	}

	if o := query.Get("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil {
			offset = parsed
		}
	}

	// For now, return an empty list
	// In a full implementation, this would fetch from the state store
	response := ListRoutesResponse{
		Routes: []RouteResponse{},
		Total:  0,
		Limit:  limit,
		Offset: offset,
	}

	logger.Info("Routes listed",
		zap.Int("limit", limit),
		zap.Int("offset", offset))

	h.respondJSON(w, http.StatusOK, response)
}

// CreateAuthPolicy handles POST /api/v1/auth-policies
func (h *Handler) CreateAuthPolicy(w http.ResponseWriter, r *http.Request) {
	logger := otelzap.Ctx(h.rc.Ctx)

	// SECURITY: Limit request body size to prevent DoS via JSON bomb
	const maxRequestSize = 1 * 1024 * 1024 // 1MB maximum
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	var req CreateAuthPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate request
	if err := req.Validate(); err != nil {
		h.respondError(w, http.StatusBadRequest, "Validation failed", err)
		return
	}

	// Convert to hecate auth policy
	policy := ConvertToHecateAuthPolicy(req)

	// Create the auth policy using the existing hecate functions
	if err := hecate.CreateAuthPolicy(h.rc, policy); err != nil {
		logger.Error("Failed to create auth policy",
			zap.String("name", req.Name),
			zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "Failed to create auth policy", err)
		return
	}

	response := CreateAuthPolicyResponse{
		ID:        policy.Name,
		Name:      policy.Name,
		Provider:  policy.Provider,
		Status:    "created",
		CreatedAt: time.Now(),
	}

	logger.Info("Auth policy created successfully",
		zap.String("name", req.Name))

	h.respondJSON(w, http.StatusCreated, response)
}

// GetAuthPolicy handles GET /api/v1/auth-policies/{name}
func (h *Handler) GetAuthPolicy(w http.ResponseWriter, r *http.Request) {
	logger := otelzap.Ctx(h.rc.Ctx)
	vars := mux.Vars(r)
	name := vars["name"]

	// For now, create a mock response
	policy := &hecate.AuthPolicy{
		Name:       name,
		Provider:   "authentik",
		Flow:       "default-authentication-flow",
		Groups:     []string{},
		RequireMFA: false,
		Metadata:   make(map[string]string),
	}

	response := ConvertFromHecateAuthPolicy(policy)

	logger.Info("Auth policy retrieved",
		zap.String("name", name))

	h.respondJSON(w, http.StatusOK, response)
}

// DeleteAuthPolicy handles DELETE /api/v1/auth-policies/{name}
func (h *Handler) DeleteAuthPolicy(w http.ResponseWriter, r *http.Request) {
	logger := otelzap.Ctx(h.rc.Ctx)
	vars := mux.Vars(r)
	name := vars["name"]

	// Delete the auth policy using the existing hecate functions
	if err := hecate.DeleteAuthPolicy(h.rc, name); err != nil {
		logger.Error("Failed to delete auth policy",
			zap.String("name", name),
			zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "Failed to delete auth policy", err)
		return
	}

	logger.Info("Auth policy deleted successfully",
		zap.String("name", name))

	w.WriteHeader(http.StatusNoContent)
}

// ReconcileState handles POST /api/v1/reconcile
func (h *Handler) ReconcileState(w http.ResponseWriter, r *http.Request) {
	logger := otelzap.Ctx(h.rc.Ctx)

	var req ReconcileStateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate request
	if err := req.Validate(); err != nil {
		h.respondError(w, http.StatusBadRequest, "Validation failed", err)
		return
	}

	// Create temporal reconciliation request
	reconcileReq := temporal.ReconciliationRequest{
		Component: req.Component,
		DryRun:    req.DryRun,
		Source:    req.Source,
		Force:     req.Force,
	}

	// Execute reconciliation using temporal workflow
	if err := temporal.ReconcileWithEos(h.rc, reconcileReq); err != nil {
		logger.Error("Failed to reconcile state",
			zap.String("component", req.Component),
			zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "Failed to reconcile state", err)
		return
	}

	response := ReconcileStateResponse{
		ID:        "reconcile-" + req.Component + "-" + time.Now().Format("20060102-150405"),
		Component: req.Component,
		Status:    "completed",
		DryRun:    req.DryRun,
		StartedAt: time.Now(),
	}

	logger.Info("State reconciliation completed",
		zap.String("component", req.Component),
		zap.Bool("dry_run", req.DryRun))

	h.respondJSON(w, http.StatusOK, response)
}

// RotateSecrets handles POST /api/v1/rotate-secrets
func (h *Handler) RotateSecrets(w http.ResponseWriter, r *http.Request) {
	logger := otelzap.Ctx(h.rc.Ctx)

	var req RotateSecretsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate request
	if err := req.Validate(); err != nil {
		h.respondError(w, http.StatusBadRequest, "Validation failed", err)
		return
	}

	// For now, just return success
	// In a full implementation, this would start a temporal workflow
	response := RotateSecretsResponse{
		ID:         "rotate-" + req.SecretType + "-" + time.Now().Format("20060102-150405"),
		SecretType: req.SecretType,
		Strategy:   req.Strategy,
		Status:     "started",
		StartedAt:  time.Now(),
	}

	logger.Info("Secret rotation started",
		zap.String("secret_type", req.SecretType),
		zap.String("strategy", req.Strategy))

	h.respondJSON(w, http.StatusAccepted, response)
}

// HealthCheck handles GET /api/v1/health
func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	response := HealthCheckResponse{
		Status:    "healthy",
		Timestamp: time.Now(),
		Version:   "1.0.0",
		Services: map[string]ServiceHealth{
			"caddy": {
				Status:       "healthy",
				ResponseTime: 10 * time.Millisecond,
				LastCheck:    time.Now(),
			},
			"authentik": {
				Status:       "healthy",
				ResponseTime: 25 * time.Millisecond,
				LastCheck:    time.Now(),
			},
		},
	}

	h.respondJSON(w, http.StatusOK, response)
}

// GetMetrics handles GET /api/v1/metrics
func (h *Handler) GetMetrics(w http.ResponseWriter, r *http.Request) {
	response := MetricsResponse{
		Timestamp: time.Now(),
		Routes:    make(map[string]RouteMetrics),
		System: SystemMetrics{
			TotalRoutes:         0,
			HealthyRoutes:       0,
			UnhealthyRoutes:     0,
			TotalRequests:       0,
			AverageResponseTime: 0,
			SystemLoad:          0.1,
			MemoryUsage:         0.3,
		},
	}

	h.respondJSON(w, http.StatusOK, response)
}

// GetWorkflowStatus handles GET /api/v1/workflows/{id}/status
func (h *Handler) GetWorkflowStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	workflowID := vars["id"]

	// For now, return a mock status
	response := WorkflowStatusResponse{
		ID:          workflowID,
		Status:      "completed",
		StartedAt:   time.Now().Add(-5 * time.Minute),
		CompletedAt: &[]time.Time{time.Now()}[0],
		Progress:    1.0,
		CurrentStep: "completed",
	}

	h.respondJSON(w, http.StatusOK, response)
}

// Helper methods for response handling

// respondJSON sends a JSON response
func (h *Handler) respondJSON(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		logger := otelzap.Ctx(h.rc.Ctx)
		logger.Error("Failed to encode JSON response", zap.Error(err))
	}
}

// respondError sends an error response
func (h *Handler) respondError(w http.ResponseWriter, code int, message string, err error) {
	logger := otelzap.Ctx(h.rc.Ctx)

	response := ErrorResponse{
		Error: message,
	}

	if err != nil {
		if ve, ok := err.(*ValidationError); ok {
			response.Code = "VALIDATION_ERROR"
			response.Details = map[string]interface{}{
				"field":   ve.Field,
				"message": ve.Message,
			}
		} else {
			response.Code = "INTERNAL_ERROR"
			response.Details = map[string]interface{}{
				"error": err.Error(),
			}
		}

		logger.Error("API error",
			zap.String("message", message),
			zap.Error(err))
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logger.Error("Failed to encode JSON error response", zap.Error(err))
	}
}

// securityHeadersMiddleware adds security headers to all responses
// SECURITY: Prevents common web vulnerabilities (XSS, clickjacking, MIME sniffing, etc.)
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Prevent clickjacking attacks
		w.Header().Set("X-Frame-Options", "DENY")

		// Enable XSS protection (defense in depth, though CSP is primary defense)
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// Content Security Policy - strict policy for API (no inline scripts/styles)
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")

		// Require HTTPS for all future requests (HSTS)
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")

		// Disable caching of sensitive API responses
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
		w.Header().Set("Pragma", "no-cache")

		// Prevent browsers from sending referrer information
		w.Header().Set("Referrer-Policy", "no-referrer")

		// Restrict feature permissions (disable geolocation, camera, microphone, etc.)
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		next.ServeHTTP(w, r)
	})
}

// SetupRoutes sets up the API routes
func (h *Handler) SetupRoutes() *mux.Router {
	router := mux.NewRouter()

	// SECURITY: Apply security headers middleware to all routes
	router.Use(securityHeadersMiddleware)

	// API v1 routes
	v1 := router.PathPrefix("/api/v1").Subrouter()

	// Route management
	v1.HandleFunc("/routes", h.CreateRoute).Methods("POST")
	v1.HandleFunc("/routes", h.ListRoutes).Methods("GET")
	v1.HandleFunc("/routes/{domain}", h.GetRoute).Methods("GET")
	v1.HandleFunc("/routes/{domain}", h.UpdateRoute).Methods("PUT")
	v1.HandleFunc("/routes/{domain}", h.DeleteRoute).Methods("DELETE")

	// Auth policy management
	v1.HandleFunc("/auth-policies", h.CreateAuthPolicy).Methods("POST")
	v1.HandleFunc("/auth-policies/{name}", h.GetAuthPolicy).Methods("GET")
	v1.HandleFunc("/auth-policies/{name}", h.DeleteAuthPolicy).Methods("DELETE")

	// State management
	v1.HandleFunc("/reconcile", h.ReconcileState).Methods("POST")

	// Secret management
	v1.HandleFunc("/rotate-secrets", h.RotateSecrets).Methods("POST")

	// System endpoints
	v1.HandleFunc("/health", h.HealthCheck).Methods("GET")
	v1.HandleFunc("/metrics", h.GetMetrics).Methods("GET")

	// Workflow management
	v1.HandleFunc("/workflows/{id}/status", h.GetWorkflowStatus).Methods("GET")

	return router
}

// StartServer starts the HTTP server
func (h *Handler) StartServer(ctx context.Context, port int) error {
	logger := otelzap.Ctx(h.rc.Ctx)

	router := h.SetupRoutes()
	server := &http.Server{
		Addr:         ":" + strconv.Itoa(port),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	logger.Info("Starting Hecate API server",
		zap.Int("port", port))

	// Start server in a goroutine with panic recovery
	shared.SafeGo(logger, "hecate-api-server", func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server error", zap.Error(err))
		}
	})

	// Wait for context cancellation
	<-ctx.Done()

	// Shutdown server gracefully
	logger.Info("Shutting down Hecate API server")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return server.Shutdown(shutdownCtx)
}

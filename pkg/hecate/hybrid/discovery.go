// pkg/hecate/hybrid/discovery.go

package hybrid

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RegisterBackendService registers a local backend service with the cloud frontend
func RegisterBackendService(rc *eos_io.RuntimeContext, backend *Backend) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check if operation is possible
	logger.Info("Assessing backend registration prerequisites",
		zap.String("name", backend.Name),
		zap.String("local_address", backend.LocalAddress),
		zap.String("public_domain", backend.PublicDomain))

	// Validate connectivity to local Consul
	localConsul, err := getLocalConsulClient(rc)
	if err != nil {
		return fmt.Errorf("failed to connect to local Consul: %w", err)
	}

	// Check if service exists locally
	services, _, err := localConsul.Health().Service(backend.ConsulService.Name, "", false, nil)
	if err != nil {
		return fmt.Errorf("failed to check service in local Consul: %w", err)
	}
	if len(services) == 0 {
		return eos_err.NewUserError("service %s not found in local Consul", backend.ConsulService.Name)
	}

	// Check if backend is already registered
	exists, err := backendExists(rc, backend.ID)
	if err != nil {
		return fmt.Errorf("failed to check backend existence: %w", err)
	}
	if exists {
		return eos_err.NewUserError("backend %s already registered", backend.ID)
	}

	// INTERVENE - Perform the registration
	logger.Info("Registering backend service with hybrid cloud setup",
		zap.String("backend_id", backend.ID))

	// Step 1: Register in local Consul with mesh gateway configuration
	registration := &api.AgentServiceRegistration{
		ID:   backend.ID,
		Name: backend.ConsulService.Name,
		Port: backend.ConsulService.Port,
		Tags: append(backend.ConsulService.Tags, "hybrid-backend", backend.BackendDC),
		Meta: map[string]string{
			"public-domain":  backend.PublicDomain,
			"frontend-dc":    backend.FrontendDC,
			"backend-dc":     backend.BackendDC,
			"hybrid-backend": "true",
			"created-by":     "eos-hecate",
		},
		Check: &api.AgentServiceCheck{
			HTTP:                           backend.HealthCheck.HTTP,
			Interval:                       backend.HealthCheck.Interval.String(),
			Timeout:                        backend.HealthCheck.Timeout.String(),
			DeregisterCriticalServiceAfter: backend.HealthCheck.DeregisterAfter.String(),
		},
	}

	// Enable Consul Connect if configured
	if backend.ConsulService.Connect {
		registration.Connect = &api.AgentServiceConnect{
			SidecarService: &api.AgentServiceRegistration{
				Proxy: &api.AgentServiceConnectProxyConfig{
					MeshGateway: api.MeshGatewayConfig{
						Mode: api.MeshGatewayModeLocal,
					},
				},
			},
		}
	}

	if err := localConsul.Agent().ServiceRegister(registration); err != nil {
		return fmt.Errorf("failed to register service in local Consul: %w", err)
	}

	// Step 2: Create prepared query for cross-DC service discovery
	if err := createCrossDCQuery(rc, backend); err != nil {
		// Rollback local registration
		_ = localConsul.Agent().ServiceDeregister(backend.ID)
		return fmt.Errorf("failed to create cross-DC query: %w", err)
	}

	// Step 3: Configure frontend route in cloud Hecate
	if err := createFrontendRoute(rc, backend); err != nil {
		// Rollback local registration and query
		_ = localConsul.Agent().ServiceDeregister(backend.ID)
		_ = deleteCrossDCQuery(rc, backend)
		return fmt.Errorf("failed to create frontend route: %w", err)
	}

	// Step 4: Store backend configuration in state
	if err := storeBackendConfig(rc, backend); err != nil {
		logger.Warn("Failed to store backend configuration",
			zap.Error(err))
		// Non-fatal - continue
	}

	// EVALUATE - Verify the registration succeeded
	logger.Info("Evaluating backend registration success")

	// Verify connectivity through the hybrid connection
	if err := verifyHybridConnection(rc, backend); err != nil {
		logger.Warn("Backend connectivity verification failed",
			zap.Error(err),
			zap.String("backend_id", backend.ID))
		// Non-fatal - backend is registered but may need troubleshooting
	}

	logger.Info("Backend service registered successfully",
		zap.String("backend_id", backend.ID),
		zap.String("name", backend.Name),
		zap.String("public_domain", backend.PublicDomain))

	return nil
}

// DeregisterBackendService removes a backend service registration
func DeregisterBackendService(rc *eos_io.RuntimeContext, backendID string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing backend deregistration prerequisites",
		zap.String("backend_id", backendID))

	// Check if backend exists
	backend, err := getBackendConfig(rc, backendID)
	if err != nil {
		return fmt.Errorf("failed to get backend config: %w", err)
	}
	if backend == nil {
		return eos_err.NewUserError("backend %s not found", backendID)
	}

	// INTERVENE
	logger.Info("Deregistering backend service",
		zap.String("backend_id", backendID))

	// Remove from local Consul
	localConsul, err := getLocalConsulClient(rc)
	if err != nil {
		logger.Warn("Failed to connect to local Consul for deregistration",
			zap.Error(err))
	} else {
		if err := localConsul.Agent().ServiceDeregister(backendID); err != nil {
			logger.Warn("Failed to deregister from local Consul",
				zap.Error(err))
		}
	}

	// Remove cross-DC query
	if err := deleteCrossDCQuery(rc, backend); err != nil {
		logger.Warn("Failed to delete cross-DC query",
			zap.Error(err))
	}

	// Remove frontend route
	if err := deleteFrontendRoute(rc, backend); err != nil {
		logger.Warn("Failed to delete frontend route",
			zap.Error(err))
	}

	// Remove from state store
	if err := deleteBackendConfig(rc, backendID); err != nil {
		logger.Warn("Failed to delete backend config",
			zap.Error(err))
	}

	// EVALUATE
	logger.Info("Backend deregistration completed",
		zap.String("backend_id", backendID))

	return nil
}

// DiscoverBackendServices discovers all registered backend services
func DiscoverBackendServices(rc *eos_io.RuntimeContext) ([]*Backend, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Discovering registered backend services")

	// Get all backend configurations from state store
	backends, err := getAllBackendConfigs(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to get backend configs: %w", err)
	}

	// Update status for each backend
	for _, backend := range backends {
		if err := updateBackendStatus(rc, backend); err != nil {
			logger.Warn("Failed to update backend status",
				zap.String("backend_id", backend.ID),
				zap.Error(err))
		}
	}

	logger.Info("Backend service discovery completed",
		zap.Int("count", len(backends)))

	return backends, nil
}

// Helper functions

func getLocalConsulClient(rc *eos_io.RuntimeContext) (*api.Client, error) {
	config := api.DefaultConfig()
	// TODO: Make this configurable
	config.Address = "localhost:8500"
	
	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w", err)
	}

	// Test connection
	_, err = client.Status().Leader()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Consul: %w", err)
	}

	return client, nil
}

func getFrontendConsulClient(rc *eos_io.RuntimeContext, frontendDC string) (*api.Client, error) {
	config := api.DefaultConfig()
	// TODO: Make this configurable based on frontendDC
	config.Address = "frontend-consul.example.com:8500"
	config.Datacenter = frontendDC
	
	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create frontend Consul client: %w", err)
	}

	return client, nil
}

func createCrossDCQuery(rc *eos_io.RuntimeContext, backend *Backend) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Creating cross-DC prepared query",
		zap.String("service", backend.ConsulService.Name))

	localConsul, err := getLocalConsulClient(rc)
	if err != nil {
		return err
	}

	// Create prepared query for cross-DC service discovery
	queryName := fmt.Sprintf("%s-cross-dc", backend.Name)
	preparedQuery := &api.PreparedQueryDefinition{
		Name: queryName,
		Service: api.ServiceQuery{
			Service: backend.ConsulService.Name,
			// TODO: Configure cross-datacenter discovery
			// The actual implementation would need to handle cross-DC routing
		},
		// TODO: Add metadata support when available in Consul API
	}

	_, _, err = localConsul.PreparedQuery().Create(preparedQuery, nil)
	if err != nil {
		return fmt.Errorf("failed to create prepared query: %w", err)
	}

	logger.Info("Cross-DC prepared query created successfully",
		zap.String("query_name", queryName))

	return nil
}

func deleteCrossDCQuery(rc *eos_io.RuntimeContext, backend *Backend) error {
	logger := otelzap.Ctx(rc.Ctx)

	queryName := fmt.Sprintf("%s-cross-dc", backend.Name)
	logger.Info("Deleting cross-DC prepared query",
		zap.String("query_name", queryName))

	// TODO: Implement query deletion by name
	// This requires getting the query ID first, then deleting it
	
	return nil
}

func createFrontendRoute(rc *eos_io.RuntimeContext, backend *Backend) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Creating frontend route",
		zap.String("domain", backend.PublicDomain),
		zap.String("service", backend.ConsulService.Name))

	// Load Hecate configuration
	config, err := hecate.LoadRouteConfig(rc)
	if err != nil {
		return fmt.Errorf("failed to load Hecate config: %w", err)
	}

	// Create route configuration
	route := &hecate.Route{
		ID:       fmt.Sprintf("hybrid-%s", backend.ID),
		Domain:   backend.PublicDomain,
		Upstream: &hecate.Upstream{
			URL: fmt.Sprintf("http://%s.connect", backend.ConsulService.Name),
		},
		Headers: make(map[string]string),
		Metadata: map[string]string{
			"hybrid-backend": "true",
			"backend-id":     backend.ID,
			"backend-dc":     backend.BackendDC,
			"created-by":     "eos-hecate",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Add authentication if configured
	if backend.Authentication != nil && backend.Authentication.Policy != nil {
		// Convert hybrid AuthPolicy to hecate AuthPolicy
		route.AuthPolicy = &hecate.AuthPolicy{
			Name:       backend.Authentication.Policy.Name,
			Provider:   backend.Authentication.Policy.Provider,
			Groups:     backend.Authentication.Policy.Groups,
			RequireMFA: backend.Authentication.Policy.RequireMFA,
		}
	}

	// Add health check if configured
	if backend.HealthCheck.HTTP != "" {
		route.HealthCheck = &hecate.HealthCheck{
			Path:             "/health",
			Interval:         backend.HealthCheck.Interval,
			Timeout:          backend.HealthCheck.Timeout,
			FailureThreshold: backend.HealthCheck.FailuresBeforeCritical,
			SuccessThreshold: 2,
			Enabled:          true,
		}
	}

	// Create the route
	if err := hecate.CreateRoute(rc, config, route); err != nil {
		return fmt.Errorf("failed to create Hecate route: %w", err)
	}

	logger.Info("Frontend route created successfully",
		zap.String("domain", backend.PublicDomain),
		zap.String("route_id", route.ID))

	return nil
}

func deleteFrontendRoute(rc *eos_io.RuntimeContext, backend *Backend) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Deleting frontend route",
		zap.String("domain", backend.PublicDomain))

	// Load Hecate configuration
	config, err := hecate.LoadRouteConfig(rc)
	if err != nil {
		return fmt.Errorf("failed to load Hecate config: %w", err)
	}

	// Delete the route
	deleteOptions := &hecate.DeleteOptions{
		Force:     true,
		Backup:    false,
		RemoveDNS: true,
	}

	if err := hecate.DeleteRoute(rc, config, backend.PublicDomain, deleteOptions); err != nil {
		return fmt.Errorf("failed to delete Hecate route: %w", err)
	}

	logger.Info("Frontend route deleted successfully",
		zap.String("domain", backend.PublicDomain))

	return nil
}

func verifyHybridConnection(rc *eos_io.RuntimeContext, backend *Backend) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Verifying hybrid connection",
		zap.String("backend_id", backend.ID))

	// TODO: Implement comprehensive connectivity verification
	// This would include:
	// 1. Check if tunnel is established
	// 2. Test connectivity through the tunnel
	// 3. Verify service is reachable from frontend
	// 4. Check DNS resolution
	// 5. Verify SSL/TLS certificates
	
	return nil
}

func backendExists(rc *eos_io.RuntimeContext, backendID string) (bool, error) {
	// TODO: Check if backend exists in state store
	return false, nil
}

func storeBackendConfig(rc *eos_io.RuntimeContext, backend *Backend) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Storing backend configuration",
		zap.String("backend_id", backend.ID))
	
	// Get Consul client
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return fmt.Errorf("failed to create Consul client: %w", err)
	}
	
	// Serialize backend configuration to JSON
	backendData, err := json.Marshal(backend)
	if err != nil {
		return fmt.Errorf("failed to serialize backend configuration: %w", err)
	}
	
	// Store in Consul KV
	key := fmt.Sprintf("hecate/backends/%s", backend.ID)
	pair := &api.KVPair{
		Key:   key,
		Value: backendData,
	}
	
	_, err = client.KV().Put(pair, nil)
	if err != nil {
		return fmt.Errorf("failed to store backend configuration: %w", err)
	}
	
	logger.Info("Backend configuration stored successfully",
		zap.String("backend_id", backend.ID),
		zap.String("key", key))
	
	return nil
}

func getBackendConfig(rc *eos_io.RuntimeContext, backendID string) (*Backend, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Retrieving backend configuration",
		zap.String("backend_id", backendID))
	
	// Get Consul client
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w", err)
	}
	
	// Retrieve from Consul KV
	key := fmt.Sprintf("hecate/backends/%s", backendID)
	pair, _, err := client.KV().Get(key, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve backend configuration: %w", err)
	}
	
	if pair == nil {
		return nil, fmt.Errorf("backend configuration not found for ID: %s", backendID)
	}
	
	// Deserialize backend configuration
	var backend Backend
	err = json.Unmarshal(pair.Value, &backend)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize backend configuration: %w", err)
	}
	
	logger.Info("Backend configuration retrieved successfully",
		zap.String("backend_id", backendID))
	
	return &backend, nil
}

func getAllBackendConfigs(rc *eos_io.RuntimeContext) ([]*Backend, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Retrieving all backend configurations")
	
	// Get Consul client
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w", err)
	}
	
	// List all backend keys
	pairs, _, err := client.KV().List("hecate/backends/", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list backend configurations: %w", err)
	}
	
	backends := make([]*Backend, 0, len(pairs))
	
	for _, pair := range pairs {
		var backend Backend
		err = json.Unmarshal(pair.Value, &backend)
		if err != nil {
			logger.Warn("Failed to deserialize backend configuration",
				zap.String("key", pair.Key),
				zap.Error(err))
			continue
		}
		backends = append(backends, &backend)
	}
	
	logger.Info("All backend configurations retrieved",
		zap.Int("count", len(backends)))
	
	return backends, nil
}

func deleteBackendConfig(rc *eos_io.RuntimeContext, backendID string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Deleting backend configuration",
		zap.String("backend_id", backendID))
	
	// Get Consul client
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return fmt.Errorf("failed to create Consul client: %w", err)
	}
	
	// Delete from Consul KV
	key := fmt.Sprintf("hecate/backends/%s", backendID)
	_, err = client.KV().Delete(key, nil)
	if err != nil {
		return fmt.Errorf("failed to delete backend configuration: %w", err)
	}
	
	logger.Info("Backend configuration deleted successfully",
		zap.String("backend_id", backendID),
		zap.String("key", key))
	
	return nil
}

func updateBackendStatus(rc *eos_io.RuntimeContext, backend *Backend) error {
	// TODO: Update backend status with current health and connectivity info
	return nil
}

// CreateRemoteRoute creates a route on the remote frontend
func CreateRemoteRoute(rc *eos_io.RuntimeContext, frontendDC string, route *hecate.Route) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Creating remote route",
		zap.String("frontend_dc", frontendDC),
		zap.String("domain", route.Domain))

	// TODO: Implement remote route creation
	// This would involve:
	// 1. Connect to frontend Hecate API
	// 2. Send route creation request
	// 3. Handle authentication/authorization
	// 4. Verify route was created successfully
	
	return nil
}
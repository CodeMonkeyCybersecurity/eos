// pkg/consul/enhanced_integration.go

package consul

import (
	"fmt"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/api/watch"
	"github.com/sony/gobreaker"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// EnhancedConsulManager provides safe, high-quality and effective Consul integration
type EnhancedConsulManager struct {
	client         *api.Client
	config         *EnhancedConfig
	circuitBreaker *gobreaker.CircuitBreaker
	watchers       map[string]*watch.Plan
	watcherMutex   sync.RWMutex
	metrics        *MetricsCollector
	alerting       *AlertManager
}

// EnhancedConfig extends basic Consul configuration with features
type EnhancedConfig struct {
	Address              string            `yaml:"address"`
	Datacenter           string            `yaml:"datacenter"`
	Token                string            `yaml:"token"`
	TLSConfig            *TLSConfig        `yaml:"tls"`
	ACLConfig            *ACLConfig        `yaml:"acl"`
	RetryConfig          *RetryConfig      `yaml:"retry"`
	CircuitBreakerConfig *CBConfig         `yaml:"circuit_breaker"`
	MonitoringConfig     *MonitoringConfig `yaml:"monitoring"`
	SecurityConfig       *SecurityConfig   `yaml:"security"`
}

type TLSConfig struct {
	Enabled        bool   `yaml:"enabled"`
	CertFile       string `yaml:"cert_file"`
	KeyFile        string `yaml:"key_file"`
	CAFile         string `yaml:"ca_file"`
	VerifyIncoming bool   `yaml:"verify_incoming"`
	VerifyOutgoing bool   `yaml:"verify_outgoing"`
}

type ACLConfig struct {
	Enabled       bool   `yaml:"enabled"`
	DefaultPolicy string `yaml:"default_policy"`
	TokenPersist  bool   `yaml:"token_persist"`
}

type RetryConfig struct {
	MaxAttempts   int           `yaml:"max_attempts"`
	InitialDelay  time.Duration `yaml:"initial_delay"`
	MaxDelay      time.Duration `yaml:"max_delay"`
	BackoffFactor float64       `yaml:"backoff_factor"`
}

type CBConfig struct {
	MaxRequests uint32        `yaml:"max_requests"`
	Interval    time.Duration `yaml:"interval"`
	Timeout     time.Duration `yaml:"timeout"`
}

type MonitoringConfig struct {
	MetricsInterval time.Duration `yaml:"metrics_interval"`
	HealthCheckFreq time.Duration `yaml:"health_check_frequency"`
	AlertingEnabled bool          `yaml:"alerting_enabled"`
	AlertingWebhook string        `yaml:"alerting_webhook"`
}

type SecurityConfig struct {
	EncryptionEnabled bool     `yaml:"encryption_enabled"`
	AllowedCIDRs      []string `yaml:"allowed_cidrs"`
	DenyByDefault     bool     `yaml:"deny_by_default"`
}

// AdvancedService represents a service with enhanced capabilities
type AdvancedService struct {
	ID                   string                `json:"id"`
	Name                 string                `json:"name"`
	Tags                 []string              `json:"tags"`
	Port                 int                   `json:"port"`
	Address              string                `json:"address"`
	Meta                 map[string]string     `json:"meta"`
	HealthChecks         []AdvancedHealthCheck `json:"health_checks"`
	ConnectConfig        *ConnectConfiguration `json:"connect_config,omitempty"`
	Weights              *ServiceWeights       `json:"weights,omitempty"`
	EnableTaggedOverride bool                  `json:"enable_tagged_override"`
}

type AdvancedHealthCheck struct {
	ID                     string            `json:"id"`
	Name                   string            `json:"name"`
	Type                   string            `json:"type"` // http, tcp, script, docker, grpc, alias
	Target                 string            `json:"target"`
	Interval               string            `json:"interval"`
	Timeout                string            `json:"timeout"`
	Headers                map[string]string `json:"headers,omitempty"`
	Method                 string            `json:"method,omitempty"`
	Body                   string            `json:"body,omitempty"`
	TLSSkipVerify          bool              `json:"tls_skip_verify,omitempty"`
	StatusCodes            []int             `json:"status_codes,omitempty"`
	SuccessBeforePassing   int               `json:"success_before_passing"`
	FailuresBeforeCritical int               `json:"failures_before_critical"`
	DeregisterAfter        string            `json:"deregister_after,omitempty"`
}

type ConnectConfiguration struct {
	Native         bool                `json:"native"`
	SidecarService *SidecarService     `json:"sidecar_service,omitempty"`
	Proxy          *ProxyConfiguration `json:"proxy,omitempty"`
}

type SidecarService struct {
	Port  int                 `json:"port"`
	Proxy *ProxyConfiguration `json:"proxy,omitempty"`
}

type ProxyConfiguration struct {
	Upstreams []UpstreamConfig       `json:"upstreams"`
	Config    map[string]interface{} `json:"config,omitempty"`
}

type UpstreamConfig struct {
	DestinationName      string                 `json:"destination_name"`
	DestinationNamespace string                 `json:"destination_namespace,omitempty"`
	LocalBindPort        int                    `json:"local_bind_port"`
	Datacenter           string                 `json:"datacenter,omitempty"`
	Config               map[string]interface{} `json:"config,omitempty"`
}

type ServiceWeights struct {
	Passing int `json:"passing"`
	Warning int `json:"warning"`
}

// NewEnhancedConsulManager creates a new enhanced Consul manager
func NewEnhancedConsulManager(rc *eos_io.RuntimeContext, config *EnhancedConfig) (*EnhancedConsulManager, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Create Consul client with enhanced configuration
	consulConfig := api.DefaultConfig()
	consulConfig.Address = config.Address
	consulConfig.Datacenter = config.Datacenter
	consulConfig.Token = config.Token

	// Configure TLS if enabled
	if config.TLSConfig != nil && config.TLSConfig.Enabled {
		tlsConfig := &api.TLSConfig{
			CertFile:           config.TLSConfig.CertFile,
			KeyFile:            config.TLSConfig.KeyFile,
			CAFile:             config.TLSConfig.CAFile,
			InsecureSkipVerify: !config.TLSConfig.VerifyIncoming,
		}
		consulConfig.TLSConfig = *tlsConfig
	}

	client, err := api.NewClient(consulConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w", err)
	}

	// Configure circuit breaker
	cbSettings := gobreaker.Settings{
		Name:        "consul-client",
		MaxRequests: config.CircuitBreakerConfig.MaxRequests,
		Interval:    config.CircuitBreakerConfig.Interval,
		Timeout:     config.CircuitBreakerConfig.Timeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
			return counts.Requests >= 3 && failureRatio >= 0.6
		},
		OnStateChange: func(name string, from gobreaker.State, to gobreaker.State) {
			logger.Warn("Circuit breaker state changed",
				zap.String("name", name),
				zap.String("from", from.String()),
				zap.String("to", to.String()))
		},
	}

	manager := &EnhancedConsulManager{
		client:         client,
		config:         config,
		circuitBreaker: gobreaker.NewCircuitBreaker(cbSettings),
		watchers:       make(map[string]*watch.Plan),
		metrics:        NewMetricsCollector(client),
		alerting:       NewAlertManager(config.MonitoringConfig),
	}

	// Start background monitoring
	if config.MonitoringConfig.MetricsInterval > 0 {
		go manager.startMetricsCollection(rc)
	}

	logger.Info("Enhanced Consul manager initialized",
		zap.String("address", config.Address),
		zap.String("datacenter", config.Datacenter))

	return manager, nil
}

// RegisterAdvancedService registers a service with enhanced capabilities
func (m *EnhancedConsulManager) RegisterAdvancedService(rc *eos_io.RuntimeContext, service AdvancedService) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Convert to Consul service registration
	registration := &api.AgentServiceRegistration{
		ID:                service.ID,
		Name:              service.Name,
		Tags:              service.Tags,
		Port:              service.Port,
		Address:           service.Address,
		Meta:              service.Meta,
		EnableTagOverride: service.EnableTaggedOverride,
	}

	// Add weights if specified
	if service.Weights != nil {
		registration.Weights = &api.AgentWeights{
			Passing: service.Weights.Passing,
			Warning: service.Weights.Warning,
		}
	}

	// Convert health checks
	for _, hc := range service.HealthChecks {
		check := &api.AgentServiceCheck{
			CheckID:                        hc.ID,
			Name:                           hc.Name,
			Interval:                       hc.Interval,
			Timeout:                        hc.Timeout,
			SuccessBeforePassing:           hc.SuccessBeforePassing,
			FailuresBeforeCritical:         hc.FailuresBeforeCritical,
			DeregisterCriticalServiceAfter: hc.DeregisterAfter,
		}

		switch hc.Type {
		case "http", "https":
			check.HTTP = hc.Target
			check.Method = hc.Method
			// Convert string map to []string map for HTTP headers
			headerMap := make(map[string][]string)
			for k, v := range hc.Headers {
				headerMap[k] = []string{v}
			}
			check.Header = headerMap
			check.Body = hc.Body
			check.TLSSkipVerify = hc.TLSSkipVerify
		case "tcp":
			check.TCP = hc.Target
		case "grpc":
			check.GRPC = hc.Target
			check.GRPCUseTLS = hc.Type == "grpc-tls"
		case "script":
			check.Args = []string{"/bin/sh", "-c", hc.Target}
		case "docker":
			check.DockerContainerID = hc.Target
			check.Shell = "/bin/sh"
		case "alias":
			check.AliasService = hc.Target
		}

		registration.Checks = append(registration.Checks, check)
	}

	// Add Connect configuration if specified
	if service.ConnectConfig != nil {
		connect := &api.AgentServiceConnect{
			Native: service.ConnectConfig.Native,
		}

		if service.ConnectConfig.SidecarService != nil {
			connect.SidecarService = &api.AgentServiceRegistration{
				Port: service.ConnectConfig.SidecarService.Port,
			}

			if service.ConnectConfig.SidecarService.Proxy != nil {
				proxy := &api.AgentServiceConnectProxyConfig{
					Config: service.ConnectConfig.SidecarService.Proxy.Config,
				}

				for _, upstream := range service.ConnectConfig.SidecarService.Proxy.Upstreams {
					proxy.Upstreams = append(proxy.Upstreams, api.Upstream{
						DestinationType:      "service",
						DestinationName:      upstream.DestinationName,
						DestinationNamespace: upstream.DestinationNamespace,
						LocalBindPort:        upstream.LocalBindPort,
						Datacenter:           upstream.Datacenter,
						Config:               upstream.Config,
					})
				}

				connect.SidecarService.Proxy = proxy
			}
		}

		registration.Connect = connect
	}

	// Register with circuit breaker protection
	_, err := m.circuitBreaker.Execute(func() (interface{}, error) {
		return nil, m.client.Agent().ServiceRegister(registration)
	})

	if err != nil {
		logger.Error("Failed to register service",
			zap.String("service", service.Name),
			zap.Error(err))
		return fmt.Errorf("service registration failed: %w", err)
	}

	logger.Info("Advanced service registered successfully",
		zap.String("service", service.Name),
		zap.String("id", service.ID),
		zap.Int("health_checks", len(service.HealthChecks)))

	return nil
}

// WatchServiceHealth monitors service health with alerting
func (m *EnhancedConsulManager) WatchServiceHealth(rc *eos_io.RuntimeContext, serviceName string, callback func(HealthEvent)) error {
	logger := otelzap.Ctx(rc.Ctx)

	watchKey := fmt.Sprintf("health_%s", serviceName)

	// Create health watch
	plan, err := watch.Parse(map[string]interface{}{
		"type":    "service",
		"service": serviceName,
	})
	if err != nil {
		return fmt.Errorf("failed to create health watch: %w", err)
	}

	plan.Handler = func(idx uint64, data interface{}) {
		if data == nil {
			return
		}

		entries := data.([]*api.ServiceEntry)

		for _, entry := range entries {
			for _, check := range entry.Checks {
				event := HealthEvent{
					ServiceName: serviceName,
					ServiceID:   entry.Service.ID,
					CheckID:     check.CheckID,
					CheckName:   check.Name,
					Status:      check.Status,
					Output:      check.Output,
					Timestamp:   time.Now(),
				}

				// Log health change
				logger.Info("Service health changed",
					zap.String("service", serviceName),
					zap.String("check", check.Name),
					zap.String("status", check.Status))

				// Trigger callback
				callback(event)

				// Send alert if critical
				if check.Status == "critical" && m.config.MonitoringConfig.AlertingEnabled {
					alert := Alert{
						Service:   serviceName,
						CheckName: check.Name,
						Status:    check.Status,
						Message:   check.Output,
						Timestamp: time.Now(),
						Severity:  "critical",
					}

					if err := m.alerting.SendAlert(alert); err != nil {
						logger.Error("Failed to send alert",
							zap.String("service", serviceName),
							zap.Error(err))
					}
				}
			}
		}
	}

	// Store watcher
	m.watcherMutex.Lock()
	m.watchers[watchKey] = plan
	m.watcherMutex.Unlock()

	// Start watching
	go func() {
		// Get client address from config
		clientAddr := m.config.Address
		if clientAddr == "" {
			clientAddr = fmt.Sprintf("127.0.0.1:%d", shared.PortConsul) // Default Consul address
		}
		if err := plan.Run(clientAddr); err != nil {
			logger.Error("Health watch failed",
				zap.String("service", serviceName),
				zap.Error(err))
		}
	}()

	logger.Info("Service health monitoring started",
		zap.String("service", serviceName))

	return nil
}

// HealthEvent represents a service health change event
type HealthEvent struct {
	ServiceName string    `json:"service_name"`
	ServiceID   string    `json:"service_id"`
	CheckID     string    `json:"check_id"`
	CheckName   string    `json:"check_name"`
	Status      string    `json:"status"`
	Output      string    `json:"output"`
	Timestamp   time.Time `json:"timestamp"`
}

// Alert is defined in alerting.go

// GetServiceWithFallback retrieves service with circuit breaker and caching
func (m *EnhancedConsulManager) GetServiceWithFallback(serviceName string, tag string) ([]*api.CatalogService, error) {
	result, err := m.circuitBreaker.Execute(func() (interface{}, error) {
		services, _, err := m.client.Catalog().Service(serviceName, tag, nil)
		return services, err
	})

	if err != nil {
		// Fallback to cached service data
		if cached := m.getCachedService(serviceName, tag); cached != nil {
			return cached, nil
		}
		return nil, fmt.Errorf("service discovery failed and no cache available: %w", err)
	}

	services := result.([]*api.CatalogService)

	// Update cache
	m.setCachedService(serviceName, tag, services)

	return services, nil
}

// startMetricsCollection begins collecting metrics in the background
func (m *EnhancedConsulManager) startMetricsCollection(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)
	ticker := time.NewTicker(m.config.MonitoringConfig.MetricsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := m.metrics.Collect(rc); err != nil {
				logger.Error("Failed to collect metrics", zap.Error(err))
			}
		case <-rc.Ctx.Done():
			logger.Info("Stopping metrics collection")
			return
		}
	}
}

// Placeholder methods for caching (implementation would use Redis/memory cache)
func (m *EnhancedConsulManager) getCachedService(serviceName, tag string) []*api.CatalogService {
	// Implementation would retrieve from cache
	return nil
}

func (m *EnhancedConsulManager) setCachedService(serviceName, tag string, services []*api.CatalogService) {
	// Implementation would store in cache with TTL
}

// Cleanup stops all watchers and cleanup resources
func (m *EnhancedConsulManager) Cleanup() {
	m.watcherMutex.Lock()
	defer m.watcherMutex.Unlock()

	for key, plan := range m.watchers {
		plan.Stop()
		delete(m.watchers, key)
	}
}

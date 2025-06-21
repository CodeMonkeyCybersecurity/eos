// Package hecate defines domain entities for reverse proxy and service orchestration
package hecate

import (
	"time"
)

// Core domain entities

// ReverseProxySpec defines the specification for reverse proxy deployment
type ReverseProxySpec struct {
	Name          string            `json:"name"`
	Version       string            `json:"version"`
	Domain        string            `json:"domain"`
	Subdomains    []string          `json:"subdomains,omitempty"`
	ProxyType     ProxyType         `json:"proxy_type"`
	Configuration *ProxyConfiguration `json:"configuration"`
	Labels        map[string]string `json:"labels,omitempty"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

// Deployment represents a reverse proxy deployment instance
type Deployment struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Spec          *ReverseProxySpec `json:"spec"`
	Status        DeploymentStatus  `json:"status"`
	StatusMessage string            `json:"status_message,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
	DeployedAt    *time.Time        `json:"deployed_at,omitempty"`
	Version       int               `json:"version"`
	Labels        map[string]string `json:"labels,omitempty"`
	Endpoints     []ProxyEndpoint   `json:"endpoints,omitempty"`
}

// DeploymentVersion represents a deployment version for rollback capability
type DeploymentVersion struct {
	Version     int               `json:"version"`
	Spec        *ReverseProxySpec `json:"spec"`
	DeployedAt  time.Time         `json:"deployed_at"`
	DeployedBy  string            `json:"deployed_by"`
	Status      DeploymentStatus  `json:"status"`
	Description string            `json:"description,omitempty"`
}

// ProxyConfiguration defines reverse proxy configuration
type ProxyConfiguration struct {
	ID                string                     `json:"id"`
	DeploymentID      string                     `json:"deployment_id"`
	Type              ConfigurationType          `json:"type"`
	Status            ConfigurationStatus        `json:"status"`
	ListenPorts       []ProxyPort                `json:"listen_ports"`
	Routes            []ProxyRoute               `json:"routes"`
	Backends          []Backend                  `json:"backends"`
	LoadBalancing     *LoadBalancingConfig       `json:"load_balancing,omitempty"`
	SSL               *SSLConfiguration          `json:"ssl,omitempty"`
	Authentication    *AuthenticationConfig      `json:"authentication,omitempty"`
	RateLimiting      *RateLimitingConfig        `json:"rate_limiting,omitempty"`
	Caching           *CachingConfig             `json:"caching,omitempty"`
	Headers           *HeaderManipulationConfig  `json:"headers,omitempty"`
	HealthChecks      []HealthCheckConfig        `json:"health_checks,omitempty"`
	Middleware        []MiddlewareConfig         `json:"middleware,omitempty"`
	CustomConfig      map[string]interface{}     `json:"custom_config,omitempty"`
	CreatedAt         time.Time                  `json:"created_at"`
	UpdatedAt         time.Time                  `json:"updated_at"`
}

// ProxyPort defines a listening port configuration
type ProxyPort struct {
	Port     int      `json:"port"`
	Protocol string   `json:"protocol"` // http, https, tcp, udp
	SSL      bool     `json:"ssl"`
	Domains  []string `json:"domains,omitempty"`
}

// ProxyRoute defines a routing rule
type ProxyRoute struct {
	ID          string            `json:"id"`
	Path        string            `json:"path"`
	PathType    PathMatchType     `json:"path_type"` // exact, prefix, regex
	Methods     []string          `json:"methods,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	QueryParams map[string]string `json:"query_params,omitempty"`
	Backend     string            `json:"backend"` // Backend ID
	Rewrite     *RewriteRule      `json:"rewrite,omitempty"`
	Timeout     *time.Duration    `json:"timeout,omitempty"`
	Priority    int               `json:"priority"`
	Enabled     bool              `json:"enabled"`
}

// Backend defines a backend service
type Backend struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Type            BackendType       `json:"type"`
	Targets         []BackendTarget   `json:"targets"`
	HealthCheck     *HealthCheck      `json:"health_check,omitempty"`
	LoadBalancing   LoadBalancePolicy `json:"load_balancing"`
	CircuitBreaker  *CircuitBreakerConfig `json:"circuit_breaker,omitempty"`
	RetryPolicy     *RetryPolicy      `json:"retry_policy,omitempty"`
	Timeout         time.Duration     `json:"timeout"`
	MaxConnections  int               `json:"max_connections,omitempty"`
	Weight          int               `json:"weight"`
	Enabled         bool              `json:"enabled"`
	Labels          map[string]string `json:"labels,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

// BackendTarget defines a backend target endpoint
type BackendTarget struct {
	ID        string            `json:"id"`
	Address   string            `json:"address"`
	Port      int               `json:"port"`
	Weight    int               `json:"weight"`
	Health    HealthStatusType  `json:"health"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	LastCheck *time.Time        `json:"last_check,omitempty"`
}

// ProxyEndpoint represents an exposed proxy endpoint
type ProxyEndpoint struct {
	URL       string            `json:"url"`
	Port      int               `json:"port"`
	Protocol  string            `json:"protocol"`
	SSL       bool              `json:"ssl"`
	Domain    string            `json:"domain"`
	Path      string            `json:"path,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

// ProxyStatus represents current proxy status
type ProxyStatus struct {
	DeploymentID     string               `json:"deployment_id"`
	Status           DeploymentStatus     `json:"status"`
	Health           HealthStatusType     `json:"health"`
	Uptime           time.Duration        `json:"uptime"`
	ActiveConnections int                 `json:"active_connections"`
	TotalRequests    int64                `json:"total_requests"`
	ErrorRate        float64              `json:"error_rate"`
	ResponseTime     time.Duration        `json:"avg_response_time"`
	BackendStatus    []BackendStatus      `json:"backend_status"`
	LastUpdate       time.Time            `json:"last_update"`
	Version          int                  `json:"version"`
}

// BackendStatus represents backend health status
type BackendStatus struct {
	BackendID        string           `json:"backend_id"`
	Name             string           `json:"name"`
	Health           HealthStatusType `json:"health"`
	ActiveTargets    int              `json:"active_targets"`
	TotalTargets     int              `json:"total_targets"`
	ResponseTime     time.Duration    `json:"avg_response_time"`
	RequestCount     int64            `json:"request_count"`
	ErrorCount       int64            `json:"error_count"`
	LastHealthCheck  *time.Time       `json:"last_health_check,omitempty"`
}

// ProxyMetrics represents proxy performance metrics
type ProxyMetrics struct {
	DeploymentID      string                    `json:"deployment_id"`
	Timestamp         time.Time                 `json:"timestamp"`
	RequestRate       float64                   `json:"request_rate"`      // requests per second
	ErrorRate         float64                   `json:"error_rate"`        // percentage
	ResponseTime      *ResponseTimeMetrics      `json:"response_time"`
	Throughput        *ThroughputMetrics        `json:"throughput"`
	ConnectionMetrics *ConnectionMetrics        `json:"connections"`
	BackendMetrics    []BackendMetrics          `json:"backend_metrics"`
	StatusCodes       map[string]int64          `json:"status_codes"`
	TopPaths          []PathMetrics             `json:"top_paths"`
}

// ResponseTimeMetrics represents response time statistics
type ResponseTimeMetrics struct {
	Average     time.Duration `json:"average"`
	P50         time.Duration `json:"p50"`
	P90         time.Duration `json:"p90"`
	P95         time.Duration `json:"p95"`
	P99         time.Duration `json:"p99"`
	Min         time.Duration `json:"min"`
	Max         time.Duration `json:"max"`
}

// ThroughputMetrics represents throughput statistics
type ThroughputMetrics struct {
	BytesIn      int64   `json:"bytes_in"`
	BytesOut     int64   `json:"bytes_out"`
	RequestsIn   int64   `json:"requests_in"`
	RequestsOut  int64   `json:"requests_out"`
	Bandwidth    float64 `json:"bandwidth_mbps"`
}

// ConnectionMetrics represents connection statistics
type ConnectionMetrics struct {
	Active      int     `json:"active"`
	Total       int64   `json:"total"`
	Failed      int64   `json:"failed"`
	Rate        float64 `json:"connection_rate"`
	AvgDuration time.Duration `json:"avg_duration"`
}

// BackendMetrics represents backend-specific metrics
type BackendMetrics struct {
	BackendID    string        `json:"backend_id"`
	RequestCount int64         `json:"request_count"`
	ErrorCount   int64         `json:"error_count"`
	ResponseTime time.Duration `json:"avg_response_time"`
	Throughput   float64       `json:"throughput_mbps"`
}

// PathMetrics represents path-specific metrics
type PathMetrics struct {
	Path         string        `json:"path"`
	RequestCount int64         `json:"request_count"`
	ErrorCount   int64         `json:"error_count"`
	ResponseTime time.Duration `json:"avg_response_time"`
}

// ProxyEvent represents proxy-related events
type ProxyEvent struct {
	ID           string            `json:"id"`
	DeploymentID string            `json:"deployment_id"`
	Type         EventType         `json:"type"`
	Timestamp    time.Time         `json:"timestamp"`
	Source       string            `json:"source"`
	Message      string            `json:"message"`
	Data         map[string]interface{} `json:"data,omitempty"`
	Severity     EventSeverity     `json:"severity"`
}

// Service orchestration entities

// ServiceProvider defines a pluggable service implementation
type ServiceProvider struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Type         ServiceType       `json:"type"`
	Version      string            `json:"version"`
	Description  string            `json:"description"`
	Dependencies []string          `json:"dependencies"`
	Capabilities []string          `json:"capabilities"`
	Configuration *ServiceConfiguration `json:"configuration"`
	Labels       map[string]string `json:"labels,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

// ServiceRegistration represents service registration information
type ServiceRegistration struct {
	ID          string            `json:"id"`
	ServiceID   string            `json:"service_id"`
	Name        string            `json:"name"`
	Type        ServiceType       `json:"type"`
	Address     string            `json:"address"`
	Port        int               `json:"port"`
	Health      HealthStatusType  `json:"health"`
	Tags        []string          `json:"tags,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	RegisteredAt time.Time        `json:"registered_at"`
	LastSeen    time.Time         `json:"last_seen"`
	TTL         time.Duration     `json:"ttl"`
}

// StackSpec defines a multi-service stack specification
type StackSpec struct {
	Name         string                        `json:"name"`
	Version      string                        `json:"version"`
	Description  string                        `json:"description"`
	Services     map[string]*ServiceSpec       `json:"services"`
	Networks     map[string]*NetworkSpec       `json:"networks,omitempty"`
	Volumes      map[string]*VolumeSpec        `json:"volumes,omitempty"`
	Configs      map[string]*ConfigSpec        `json:"configs,omitempty"`
	Secrets      map[string]*SecretSpec        `json:"secrets,omitempty"`
	Dependencies []string                      `json:"dependencies,omitempty"`
	Labels       map[string]string             `json:"labels,omitempty"`
}

// ServiceSpec defines an individual service specification
type ServiceSpec struct {
	Name         string                 `json:"name"`
	Image        string                 `json:"image"`
	Replicas     int                    `json:"replicas"`
	Ports        []ServicePort          `json:"ports,omitempty"`
	Environment  map[string]string      `json:"environment,omitempty"`
	Volumes      []ServiceVolume        `json:"volumes,omitempty"`
	Networks     []string               `json:"networks,omitempty"`
	Dependencies []string               `json:"depends_on,omitempty"`
	HealthCheck  *HealthCheckConfig     `json:"health_check,omitempty"`
	Resources    *ResourceConstraints   `json:"resources,omitempty"`
	Security     *SecurityConfig        `json:"security,omitempty"`
	Labels       map[string]string      `json:"labels,omitempty"`
	Annotations  map[string]string      `json:"annotations,omitempty"`
}

// ServicePort defines service port configuration
type ServicePort struct {
	Target    int    `json:"target"`
	Published int    `json:"published,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Mode      string `json:"mode,omitempty"`
}

// ServiceVolume defines service volume mount
type ServiceVolume struct {
	Type   string `json:"type"`   // bind, volume, tmpfs
	Source string `json:"source"` // host path or volume name
	Target string `json:"target"` // container path
	ReadOnly bool `json:"read_only,omitempty"`
}

// StackDeployment represents a deployed stack
type StackDeployment struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Spec         *StackSpec        `json:"spec"`
	Status       DeploymentStatus  `json:"status"`
	Services     []ServiceInstance `json:"services"`
	Networks     []Network         `json:"networks,omitempty"`
	Volumes      []Volume          `json:"volumes,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
	DeployedAt   *time.Time        `json:"deployed_at,omitempty"`
	Version      int               `json:"version"`
	Labels       map[string]string `json:"labels,omitempty"`
}

// StackStatus represents stack deployment status
type StackStatus struct {
	StackID       string              `json:"stack_id"`
	Name          string              `json:"name"`
	Status        DeploymentStatus    `json:"status"`
	Health        HealthStatusType    `json:"health"`
	ServiceCount  int                 `json:"service_count"`
	RunningCount  int                 `json:"running_services"`
	Services      []ServiceStatus     `json:"services"`
	LastUpdate    time.Time           `json:"last_update"`
	Version       int                 `json:"version"`
}

// ServiceInstance represents a running service instance
type ServiceInstance struct {
	ID           string               `json:"id"`
	ServiceID    string               `json:"service_id"`
	Name         string               `json:"name"`
	Type         ServiceType          `json:"type"`
	Status       ServiceStatus        `json:"status"`
	Health       HealthStatusType     `json:"health"`
	Address      string               `json:"address"`
	Port         int                  `json:"port"`
	Endpoints    []ServiceEndpoint    `json:"endpoints,omitempty"`
	Labels       map[string]string    `json:"labels,omitempty"`
	CreatedAt    time.Time            `json:"created_at"`
	UpdatedAt    time.Time            `json:"updated_at"`
	StartedAt    *time.Time           `json:"started_at,omitempty"`
}

// ServiceEndpoint represents a service endpoint
type ServiceEndpoint struct {
	URL      string `json:"url"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Health   HealthStatusType `json:"health"`
}

// ServiceStatus represents service status information
type ServiceStatus struct {
	ServiceID     string           `json:"service_id"`
	Name          string           `json:"name"`
	State         ServiceState     `json:"state"`
	Health        HealthStatusType `json:"health"`
	Replicas      int              `json:"replicas"`
	ReadyReplicas int              `json:"ready_replicas"`
	UpdatedAt     time.Time        `json:"updated_at"`
}

// Configuration management entities

// ServiceConfiguration represents service configuration
type ServiceConfiguration struct {
	ID           string                 `json:"id"`
	ServiceID    string                 `json:"service_id"`
	Name         string                 `json:"name"`
	Type         ConfigurationType      `json:"type"`
	Status       ConfigurationStatus    `json:"status"`
	Data         map[string]interface{} `json:"data"`
	Schema       *ConfigurationSchema   `json:"schema,omitempty"`
	Version      int                    `json:"version"`
	Description  string                 `json:"description,omitempty"`
	Labels       map[string]string      `json:"labels,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
	CreatedBy    string                 `json:"created_by"`
}

// ConfigurationSchema defines configuration validation schema
type ConfigurationSchema struct {
	Type       string                            `json:"type"`
	Properties map[string]*ConfigurationProperty `json:"properties"`
	Required   []string                          `json:"required,omitempty"`
}

// ConfigurationProperty defines a configuration property
type ConfigurationProperty struct {
	Type        string      `json:"type"`
	Description string      `json:"description,omitempty"`
	Default     interface{} `json:"default,omitempty"`
	Enum        []interface{} `json:"enum,omitempty"`
	Pattern     string      `json:"pattern,omitempty"`
	Minimum     *float64    `json:"minimum,omitempty"`
	Maximum     *float64    `json:"maximum,omitempty"`
}

// ConfigurationTemplate represents a configuration template
type ConfigurationTemplate struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        ConfigurationType      `json:"type"`
	Description string                 `json:"description"`
	Template    string                 `json:"template"`
	Variables   []TemplateVariable     `json:"variables"`
	Schema      *ConfigurationSchema   `json:"schema,omitempty"`
	Labels      map[string]string      `json:"labels,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// TemplateVariable defines a template variable
type TemplateVariable struct {
	Name        string      `json:"name"`
	Type        string      `json:"type"`
	Description string      `json:"description"`
	Default     interface{} `json:"default,omitempty"`
	Required    bool        `json:"required"`
}

// ConfigurationVersion represents a configuration version
type ConfigurationVersion struct {
	Version   int       `json:"version"`
	Config    *ServiceConfiguration `json:"config"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
	Message   string    `json:"message,omitempty"`
}

// ConfigurationBackup represents a configuration backup
type ConfigurationBackup struct {
	ID          string    `json:"id"`
	ServiceID   string    `json:"service_id"`
	ConfigID    string    `json:"config_id"`
	BackupPath  string    `json:"backup_path"`
	Size        int64     `json:"size"`
	Checksum    string    `json:"checksum"`
	CreatedAt   time.Time `json:"created_at"`
	Description string    `json:"description,omitempty"`
}

// Certificate management entities

// CertificateSpec defines certificate request specification
type CertificateSpec struct {
	CommonName       string   `json:"common_name"`
	AlternativeNames []string `json:"alternative_names,omitempty"`
	Organization     string   `json:"organization,omitempty"`
	Country          string   `json:"country,omitempty"`
	ValidityDays     int      `json:"validity_days"`
	KeySize          int      `json:"key_size,omitempty"`
	CertType         CertificateType `json:"cert_type"`
	AutoRenew        bool     `json:"auto_renew"`
}

// Certificate represents a TLS certificate
type Certificate struct {
	ID               string            `json:"id"`
	CommonName       string            `json:"common_name"`
	AlternativeNames []string          `json:"alternative_names,omitempty"`
	Status           CertificateStatus `json:"status"`
	CertData         string            `json:"cert_data,omitempty"`
	KeyData          string            `json:"key_data,omitempty"`
	ChainData        string            `json:"chain_data,omitempty"`
	Issuer           string            `json:"issuer"`
	Serial           string            `json:"serial"`
	NotBefore        time.Time         `json:"not_before"`
	NotAfter         time.Time         `json:"not_after"`
	Fingerprint      string            `json:"fingerprint"`
	AutoRenew        bool              `json:"auto_renew"`
	RenewBefore      time.Duration     `json:"renew_before"`
	Labels           map[string]string `json:"labels,omitempty"`
	CreatedAt        time.Time         `json:"created_at"`
	UpdatedAt        time.Time         `json:"updated_at"`
}

// CertificateValidation represents certificate validation result
type CertificateValidation struct {
	CertificateID string                   `json:"certificate_id"`
	Valid         bool                     `json:"valid"`
	Errors        []string                 `json:"errors,omitempty"`
	Warnings      []string                 `json:"warnings,omitempty"`
	ExpiresIn     time.Duration            `json:"expires_in"`
	Details       *CertificateDetails      `json:"details,omitempty"`
	ValidatedAt   time.Time                `json:"validated_at"`
}

// CertificateDetails represents detailed certificate information
type CertificateDetails struct {
	Subject    *CertificateSubject `json:"subject"`
	Issuer     *CertificateSubject `json:"issuer"`
	Extensions []CertificateExtension `json:"extensions,omitempty"`
	KeyUsage   []string            `json:"key_usage,omitempty"`
	PublicKey  *PublicKeyInfo      `json:"public_key"`
}

// CertificateSubject represents certificate subject information
type CertificateSubject struct {
	CommonName   string `json:"common_name"`
	Organization string `json:"organization,omitempty"`
	Country      string `json:"country,omitempty"`
	State        string `json:"state,omitempty"`
	Locality     string `json:"locality,omitempty"`
}

// CertificateExtension represents a certificate extension
type CertificateExtension struct {
	OID      string `json:"oid"`
	Critical bool   `json:"critical"`
	Value    string `json:"value"`
}

// PublicKeyInfo represents public key information
type PublicKeyInfo struct {
	Algorithm string `json:"algorithm"`
	Size      int    `json:"size"`
	Curve     string `json:"curve,omitempty"`
}

// CertificateEvent represents certificate-related events
type CertificateEvent struct {
	ID            string    `json:"id"`
	CertificateID string    `json:"certificate_id"`
	Type          EventType `json:"type"`
	Timestamp     time.Time `json:"timestamp"`
	Message       string    `json:"message"`
	Data          map[string]interface{} `json:"data,omitempty"`
}

// Network management entities

// NetworkSpec defines network creation specification
type NetworkSpec struct {
	Name      string            `json:"name"`
	Driver    string            `json:"driver"`
	IPAM      *NetworkIPAM      `json:"ipam,omitempty"`
	Options   map[string]string `json:"options,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	Internal  bool              `json:"internal,omitempty"`
	Attachable bool             `json:"attachable,omitempty"`
}

// Network represents a container network
type Network struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Driver   string            `json:"driver"`
	Scope    string            `json:"scope"`
	IPAM     *NetworkIPAM      `json:"ipam,omitempty"`
	Options  map[string]string `json:"options,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
	Internal bool              `json:"internal"`
	Created  time.Time         `json:"created"`
}

// NetworkIPAM represents IP Address Management configuration
type NetworkIPAM struct {
	Driver  string              `json:"driver"`
	Config  []NetworkIPAMConfig `json:"config,omitempty"`
	Options map[string]string   `json:"options,omitempty"`
}

// NetworkIPAMConfig represents IPAM configuration
type NetworkIPAMConfig struct {
	Subnet     string `json:"subnet"`
	IPRange    string `json:"ip_range,omitempty"`
	Gateway    string `json:"gateway,omitempty"`
	AuxAddress map[string]string `json:"aux_addresses,omitempty"`
}

// NetworkPolicy defines network security policies
type NetworkPolicy struct {
	ID          string                `json:"id"`
	Name        string                `json:"name"`
	NetworkID   string                `json:"network_id"`
	Rules       []NetworkPolicyRule   `json:"rules"`
	Labels      map[string]string     `json:"labels,omitempty"`
	CreatedAt   time.Time             `json:"created_at"`
	UpdatedAt   time.Time             `json:"updated_at"`
}

// NetworkPolicyRule defines network policy rules
type NetworkPolicyRule struct {
	ID        string            `json:"id"`
	Action    PolicyAction      `json:"action"` // allow, deny
	Direction TrafficDirection  `json:"direction"` // ingress, egress
	Protocol  string            `json:"protocol,omitempty"` // tcp, udp, icmp
	Ports     []string          `json:"ports,omitempty"`
	Sources   []string          `json:"sources,omitempty"`
	Targets   []string          `json:"targets,omitempty"`
	Priority  int               `json:"priority"`
}

// LoadBalancerSpec defines load balancer specification
type LoadBalancerSpec struct {
	Name      string                  `json:"name"`
	Type      LoadBalancerType        `json:"type"`
	Algorithm LoadBalancePolicy       `json:"algorithm"`
	Backends  []LoadBalancerBackend   `json:"backends"`
	Config    map[string]interface{}  `json:"config,omitempty"`
	Labels    map[string]string       `json:"labels,omitempty"`
}

// LoadBalancer represents a load balancer instance
type LoadBalancer struct {
	ID        string                `json:"id"`
	Name      string                `json:"name"`
	Type      LoadBalancerType      `json:"type"`
	Algorithm LoadBalancePolicy     `json:"algorithm"`
	Backends  []LoadBalancerBackend `json:"backends"`
	Status    ServiceStatus         `json:"status"`
	Address   string                `json:"address"`
	Port      int                   `json:"port"`
	CreatedAt time.Time             `json:"created_at"`
	UpdatedAt time.Time             `json:"updated_at"`
}

// LoadBalancerBackend represents a load balancer backend
type LoadBalancerBackend struct {
	ID       string           `json:"id"`
	Address  string           `json:"address"`
	Port     int              `json:"port"`
	Weight   int              `json:"weight"`
	Health   HealthStatusType `json:"health"`
	Enabled  bool             `json:"enabled"`
}

// TrafficRule defines traffic management rules
type TrafficRule struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Priority    int              `json:"priority"`
	Match       *TrafficMatch    `json:"match"`
	Action      *TrafficAction   `json:"action"`
	Enabled     bool             `json:"enabled"`
	CreatedAt   time.Time        `json:"created_at"`
}

// TrafficMatch defines traffic matching criteria
type TrafficMatch struct {
	Protocol    string            `json:"protocol,omitempty"`
	SourceIP    string            `json:"source_ip,omitempty"`
	DestIP      string            `json:"dest_ip,omitempty"`
	SourcePort  string            `json:"source_port,omitempty"`
	DestPort    string            `json:"dest_port,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Path        string            `json:"path,omitempty"`
	Method      string            `json:"method,omitempty"`
}

// TrafficAction defines traffic management actions
type TrafficAction struct {
	Type      TrafficActionType `json:"type"` // allow, deny, redirect, rate_limit
	Target    string            `json:"target,omitempty"`
	RateLimit *RateLimit        `json:"rate_limit,omitempty"`
	Redirect  *RedirectAction   `json:"redirect,omitempty"`
}

// Additional configuration entities

// LoadBalancingConfig defines load balancing configuration
type LoadBalancingConfig struct {
	Algorithm      LoadBalancePolicy `json:"algorithm"`
	SessionAffinity bool             `json:"session_affinity,omitempty"`
	AffinityType   string           `json:"affinity_type,omitempty"`
	AffinityTTL    time.Duration    `json:"affinity_ttl,omitempty"`
}

// SSLConfiguration defines SSL/TLS configuration
type SSLConfiguration struct {
	Enabled      bool     `json:"enabled"`
	CertificateID string  `json:"certificate_id"`
	Protocols    []string `json:"protocols,omitempty"`
	Ciphers      []string `json:"ciphers,omitempty"`
	HSTS         bool     `json:"hsts,omitempty"`
	Redirect     bool     `json:"redirect_http,omitempty"`
}

// AuthenticationConfig defines authentication configuration
type AuthenticationConfig struct {
	Type     AuthenticationType `json:"type"`
	Config   map[string]interface{} `json:"config"`
	Required bool               `json:"required"`
}

// RateLimitingConfig defines rate limiting configuration
type RateLimitingConfig struct {
	Enabled   bool          `json:"enabled"`
	RateLimit int           `json:"rate_limit"`
	Window    time.Duration `json:"window"`
	BurstSize int           `json:"burst_size,omitempty"`
	KeyType   string        `json:"key_type"` // ip, header, query
	KeyName   string        `json:"key_name,omitempty"`
}

// CachingConfig defines caching configuration
type CachingConfig struct {
	Enabled  bool          `json:"enabled"`
	TTL      time.Duration `json:"ttl"`
	MaxSize  int64         `json:"max_size,omitempty"`
	KeyRules []CacheKeyRule `json:"key_rules,omitempty"`
}

// CacheKeyRule defines cache key generation rules
type CacheKeyRule struct {
	Path    string   `json:"path"`
	Headers []string `json:"headers,omitempty"`
	Query   []string `json:"query,omitempty"`
}

// HeaderManipulationConfig defines header manipulation rules
type HeaderManipulationConfig struct {
	Add    map[string]string `json:"add,omitempty"`
	Set    map[string]string `json:"set,omitempty"`
	Remove []string          `json:"remove,omitempty"`
}

// HealthCheckConfig defines health check configuration
type HealthCheckConfig struct {
	ID       string        `json:"id"`
	Type     HealthCheckType `json:"type"` // http, tcp, grpc
	Path     string        `json:"path,omitempty"`
	Port     int           `json:"port,omitempty"`
	Interval time.Duration `json:"interval"`
	Timeout  time.Duration `json:"timeout"`
	Retries  int           `json:"retries"`
	Headers  map[string]string `json:"headers,omitempty"`
	Expected *HealthCheckExpected `json:"expected,omitempty"`
}

// HealthCheckExpected defines expected health check results
type HealthCheckExpected struct {
	StatusCode int    `json:"status_code,omitempty"`
	Body       string `json:"body,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
}

// MiddlewareConfig defines middleware configuration
type MiddlewareConfig struct {
	Name     string                 `json:"name"`
	Type     string                 `json:"type"`
	Config   map[string]interface{} `json:"config"`
	Priority int                    `json:"priority"`
	Enabled  bool                   `json:"enabled"`
}

// RewriteRule defines URL rewrite rules
type RewriteRule struct {
	Pattern     string `json:"pattern"`
	Replacement string `json:"replacement"`
	Regex       bool   `json:"regex,omitempty"`
}

// HealthCheck represents health check configuration
type HealthCheck struct {
	Type     HealthCheckType `json:"type"`
	Config   *HealthCheckConfig `json:"config"`
	Status   HealthStatusType `json:"status"`
	LastCheck *time.Time      `json:"last_check,omitempty"`
	Message  string          `json:"message,omitempty"`
}

// CircuitBreakerConfig defines circuit breaker configuration
type CircuitBreakerConfig struct {
	Enabled           bool          `json:"enabled"`
	FailureThreshold  int           `json:"failure_threshold"`
	RecoveryTimeout   time.Duration `json:"recovery_timeout"`
	TestRequestCount  int           `json:"test_request_count"`
}

// RetryPolicy defines retry policy configuration
type RetryPolicy struct {
	MaxRetries    int           `json:"max_retries"`
	BackoffType   string        `json:"backoff_type"` // fixed, exponential
	InitialDelay  time.Duration `json:"initial_delay"`
	MaxDelay      time.Duration `json:"max_delay"`
	RetryOnStatus []int         `json:"retry_on_status,omitempty"`
}

// ResourceConstraints defines resource constraints
type ResourceConstraints struct {
	CPULimit     string `json:"cpu_limit,omitempty"`
	CPURequest   string `json:"cpu_request,omitempty"`
	MemoryLimit  string `json:"memory_limit,omitempty"`
	MemoryRequest string `json:"memory_request,omitempty"`
}

// SecurityConfig defines security configuration
type SecurityConfig struct {
	RunAsUser     *int64  `json:"run_as_user,omitempty"`
	RunAsGroup    *int64  `json:"run_as_group,omitempty"`
	ReadOnlyRoot  bool    `json:"read_only_root,omitempty"`
	Privileged    bool    `json:"privileged,omitempty"`
	Capabilities  *SecurityCapabilities `json:"capabilities,omitempty"`
}

// SecurityCapabilities defines Linux capabilities
type SecurityCapabilities struct {
	Add  []string `json:"add,omitempty"`
	Drop []string `json:"drop,omitempty"`
}

// Additional helper types

// Event represents a system event
type Event struct {
	ID        string                 `json:"id"`
	Type      EventType              `json:"type"`
	Source    string                 `json:"source"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
	Severity  EventSeverity          `json:"severity"`
}

// Subscription represents an event subscription
type Subscription struct {
	ID       string    `json:"id"`
	Pattern  string    `json:"pattern"`
	Handler  string    `json:"handler"`
	Active   bool      `json:"active"`
	Created  time.Time `json:"created"`
}

// HealthStatus represents health status information
type HealthStatus struct {
	Status    HealthStatusType `json:"status"`
	Message   string           `json:"message,omitempty"`
	Timestamp time.Time        `json:"timestamp"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// HealthReport represents a health check report
type HealthReport struct {
	ServiceID string           `json:"service_id"`
	Status    HealthStatusType `json:"status"`
	Checks    []HealthCheck    `json:"checks"`
	Timestamp time.Time        `json:"timestamp"`
	Duration  time.Duration    `json:"duration"`
}

// ServiceMetrics represents service performance metrics
type ServiceMetrics struct {
	ServiceID     string                 `json:"service_id"`
	Timestamp     time.Time              `json:"timestamp"`
	CPU           *CPUMetrics            `json:"cpu,omitempty"`
	Memory        *MemoryMetrics         `json:"memory,omitempty"`
	Network       *NetworkMetrics        `json:"network,omitempty"`
	Requests      *RequestMetrics        `json:"requests,omitempty"`
	CustomMetrics map[string]interface{} `json:"custom_metrics,omitempty"`
}

// CPUMetrics represents CPU usage metrics
type CPUMetrics struct {
	Usage     float64 `json:"usage_percent"`
	Cores     int     `json:"cores"`
	Throttled int64   `json:"throttled_periods"`
}

// MemoryMetrics represents memory usage metrics
type MemoryMetrics struct {
	Usage   int64   `json:"usage_bytes"`
	Limit   int64   `json:"limit_bytes"`
	Percent float64 `json:"usage_percent"`
	Cache   int64   `json:"cache_bytes"`
}

// NetworkMetrics represents network usage metrics
type NetworkMetrics struct {
	RxBytes   int64 `json:"rx_bytes"`
	TxBytes   int64 `json:"tx_bytes"`
	RxPackets int64 `json:"rx_packets"`
	TxPackets int64 `json:"tx_packets"`
	Errors    int64 `json:"errors"`
}

// RequestMetrics represents request metrics
type RequestMetrics struct {
	Total        int64         `json:"total"`
	Rate         float64       `json:"rate_per_second"`
	ErrorRate    float64       `json:"error_rate_percent"`
	ResponseTime time.Duration `json:"avg_response_time"`
}

// MetricPoint represents a single metric data point
type MetricPoint struct {
	Timestamp time.Time   `json:"timestamp"`
	Value     float64     `json:"value"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// AlertRule represents an alerting rule
type AlertRule struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Query       string            `json:"query"`
	Condition   string            `json:"condition"`
	Threshold   float64           `json:"threshold"`
	Duration    time.Duration     `json:"duration"`
	Severity    AlertSeverity     `json:"severity"`
	Enabled     bool              `json:"enabled"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// HealthEvent represents a health status change event
type HealthEvent struct {
	ServiceID string           `json:"service_id"`
	OldStatus HealthStatusType `json:"old_status"`
	NewStatus HealthStatusType `json:"new_status"`
	Timestamp time.Time        `json:"timestamp"`
	Message   string           `json:"message,omitempty"`
}

// LogEntry represents a log entry
type LogEntry struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	Level     LogLevel               `json:"level"`
	Source    string                 `json:"source"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

// LogQuery represents a log search query
type LogQuery struct {
	Query     string     `json:"query"`
	StartTime *time.Time `json:"start_time,omitempty"`
	EndTime   *time.Time `json:"end_time,omitempty"`
	Limit     int        `json:"limit,omitempty"`
	Level     LogLevel   `json:"level,omitempty"`
	Source    string     `json:"source,omitempty"`
}

// LogAlert represents a log-based alert
type LogAlert struct {
	ID        string        `json:"id"`
	Name      string        `json:"name"`
	Query     string        `json:"query"`
	Threshold int           `json:"threshold"`
	Window    time.Duration `json:"window"`
	Severity  AlertSeverity `json:"severity"`
	Enabled   bool          `json:"enabled"`
	CreatedAt time.Time     `json:"created_at"`
}

// Backup and restore entities

// BackupSpec defines backup specification
type BackupSpec struct {
	ServiceID   string            `json:"service_id"`
	Type        BackupType        `json:"type"`
	Destination string            `json:"destination"`
	Schedule    string            `json:"schedule,omitempty"`
	Retention   time.Duration     `json:"retention"`
	Compression bool              `json:"compression"`
	Encryption  bool              `json:"encryption"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// Backup represents a backup instance
type Backup struct {
	ID          string     `json:"id"`
	ServiceID   string     `json:"service_id"`
	Type        BackupType `json:"type"`
	Status      BackupStatus `json:"status"`
	Path        string     `json:"path"`
	Size        int64      `json:"size"`
	Checksum    string     `json:"checksum"`
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Error       string     `json:"error,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// BackupValidation represents backup validation result
type BackupValidation struct {
	BackupID    string    `json:"backup_id"`
	Valid       bool      `json:"valid"`
	Errors      []string  `json:"errors,omitempty"`
	Warnings    []string  `json:"warnings,omitempty"`
	ValidatedAt time.Time `json:"validated_at"`
}

// BackupSchedule represents a backup schedule
type BackupSchedule struct {
	ID        string        `json:"id"`
	ServiceID string        `json:"service_id"`
	Spec      *BackupSpec   `json:"spec"`
	Schedule  string        `json:"schedule"` // cron expression
	Enabled   bool          `json:"enabled"`
	NextRun   *time.Time    `json:"next_run,omitempty"`
	LastRun   *time.Time    `json:"last_run,omitempty"`
	CreatedAt time.Time     `json:"created_at"`
	UpdatedAt time.Time     `json:"updated_at"`
}

// Additional specification types

// ConfigSpec defines configuration specification
type ConfigSpec struct {
	Name string `json:"name"`
	Data string `json:"data"`
}

// SecretSpec defines secret specification
type SecretSpec struct {
	Name string `json:"name"`
	Data string `json:"data"`
}

// VolumeSpec defines volume specification
type VolumeSpec struct {
	Name   string            `json:"name"`
	Driver string            `json:"driver,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`
}

// Volume represents a storage volume
type Volume struct {
	Name      string            `json:"name"`
	Driver    string            `json:"driver"`
	Mountpoint string           `json:"mountpoint"`
	Labels    map[string]string `json:"labels,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

// Container represents a container instance
type Container struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Image    string            `json:"image"`
	Status   ContainerStatus   `json:"status"`
	Ports    []string          `json:"ports,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
	Volumes  []ContainerVolume `json:"volumes,omitempty"`
	Networks []string          `json:"networks,omitempty"`
	Created  time.Time         `json:"created"`
}

// ContainerVolume represents a container volume mount
type ContainerVolume struct {
	Type        string `json:"type"`   // bind, volume, tmpfs
	Source      string `json:"source"` // host path or volume name
	Destination string `json:"destination"` // container path
	Mode        string `json:"mode,omitempty"` // rw, ro
}

// ContainerStats represents container resource statistics
type ContainerStats struct {
	ContainerID   string                 `json:"container_id"`
	Timestamp     time.Time              `json:"timestamp"`
	CPU           *CPUMetrics            `json:"cpu"`
	Memory        *MemoryMetrics         `json:"memory"`
	Network       map[string]*NetworkMetrics `json:"network"`
	BlockIO       *BlockIOMetrics        `json:"block_io,omitempty"`
	PIDs          *PIDMetrics            `json:"pids,omitempty"`
}

// BlockIOMetrics represents block I/O metrics
type BlockIOMetrics struct {
	ReadBytes  int64 `json:"read_bytes"`
	WriteBytes int64 `json:"write_bytes"`
	ReadOps    int64 `json:"read_ops"`
	WriteOps   int64 `json:"write_ops"`
}

// PIDMetrics represents process ID metrics
type PIDMetrics struct {
	Current int64 `json:"current"`
	Limit   int64 `json:"limit"`
}

// ExecutionResult represents command execution result
type ExecutionResult struct {
	ExitCode int           `json:"exit_code"`
	Stdout   string        `json:"stdout"`
	Stderr   string        `json:"stderr"`
	Duration time.Duration `json:"duration"`
	Error    string        `json:"error,omitempty"`
}

// RuntimeInfo represents container runtime information
type RuntimeInfo struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	APIVersion   string `json:"api_version"`
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	KernelVersion string `json:"kernel_version"`
}

// SystemUsage represents system resource usage
type SystemUsage struct {
	Containers int64           `json:"containers"`
	Images     int64           `json:"images"`
	Volumes    int64           `json:"volumes"`
	Networks   int64           `json:"networks"`
	Memory     *MemoryMetrics  `json:"memory"`
	Storage    *StorageMetrics `json:"storage"`
}

// StorageMetrics represents storage usage metrics
type StorageMetrics struct {
	Used      int64   `json:"used_bytes"`
	Available int64   `json:"available_bytes"`
	Total     int64   `json:"total_bytes"`
	Percent   float64 `json:"usage_percent"`
}

// PruneResult represents system pruning result
type PruneResult struct {
	ContainersDeleted int   `json:"containers_deleted"`
	ImagesDeleted     int   `json:"images_deleted"`
	VolumesDeleted    int   `json:"volumes_deleted"`
	NetworksDeleted   int   `json:"networks_deleted"`
	SpaceReclaimed    int64 `json:"space_reclaimed"`
}

// ContainerEvent represents a container-related event
type ContainerEvent struct {
	ID          string    `json:"id"`
	ContainerID string    `json:"container_id"`
	Action      string    `json:"action"`
	Actor       string    `json:"actor"`
	Timestamp   time.Time `json:"timestamp"`
	Attributes  map[string]string `json:"attributes,omitempty"`
}

// SearchResult represents registry search result
type SearchResult struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Stars       int    `json:"stars"`
	Official    bool   `json:"official"`
	Automated   bool   `json:"automated"`
}

// ExecConfig represents command execution configuration
type ExecConfig struct {
	Command     []string `json:"command"`
	WorkingDir  string   `json:"working_dir,omitempty"`
	Environment []string `json:"environment,omitempty"`
	User        string   `json:"user,omitempty"`
	Privileged  bool     `json:"privileged,omitempty"`
	TTY         bool     `json:"tty,omitempty"`
	AttachStdout bool    `json:"attach_stdout"`
	AttachStderr bool    `json:"attach_stderr"`
	PolicyRules []string `json:"policy_rules,omitempty"`
}

// ExecResult represents command execution result in container
type ExecResult struct {
	ExitCode int           `json:"exit_code"`
	Stdout   string        `json:"stdout"`
	Stderr   string        `json:"stderr"`
	Duration time.Duration `json:"duration"`
}

// ComposeConfig represents Docker Compose configuration
type ComposeConfig struct {
	Version  string                        `json:"version"`
	Services map[string]*ComposeService    `json:"services"`
	Networks map[string]*ComposeNetwork    `json:"networks,omitempty"`
	Volumes  map[string]*ComposeVolume     `json:"volumes,omitempty"`
	Configs  map[string]*ComposeConfigItem `json:"configs,omitempty"`
	Secrets  map[string]*ComposeSecretItem `json:"secrets,omitempty"`
}

// ComposeService represents a service in Docker Compose
type ComposeService struct {
	Image        string                 `json:"image,omitempty"`
	Build        *ComposeBuild          `json:"build,omitempty"`
	Ports        []string               `json:"ports,omitempty"`
	Environment  map[string]string      `json:"environment,omitempty"`
	Volumes      []string               `json:"volumes,omitempty"`
	Networks     []string               `json:"networks,omitempty"`
	DependsOn    []string               `json:"depends_on,omitempty"`
	Command      []string               `json:"command,omitempty"`
	Entrypoint   []string               `json:"entrypoint,omitempty"`
	WorkingDir   string                 `json:"working_dir,omitempty"`
	User         string                 `json:"user,omitempty"`
	Restart      string                 `json:"restart,omitempty"`
	HealthCheck  *ComposeHealthCheck    `json:"healthcheck,omitempty"`
	Labels       map[string]string      `json:"labels,omitempty"`
	Logging      *ComposeLogging        `json:"logging,omitempty"`
	Deploy       *ComposeDeploy         `json:"deploy,omitempty"`
}

// ComposeBuild represents build configuration
type ComposeBuild struct {
	Context    string            `json:"context"`
	Dockerfile string            `json:"dockerfile,omitempty"`
	Args       map[string]string `json:"args,omitempty"`
	Target     string            `json:"target,omitempty"`
}

// ComposeHealthCheck represents health check configuration
type ComposeHealthCheck struct {
	Test        []string      `json:"test"`
	Interval    time.Duration `json:"interval,omitempty"`
	Timeout     time.Duration `json:"timeout,omitempty"`
	Retries     int           `json:"retries,omitempty"`
	StartPeriod time.Duration `json:"start_period,omitempty"`
}

// ComposeLogging represents logging configuration
type ComposeLogging struct {
	Driver  string            `json:"driver"`
	Options map[string]string `json:"options,omitempty"`
}

// ComposeDeploy represents deployment configuration
type ComposeDeploy struct {
	Replicas  int                      `json:"replicas,omitempty"`
	Resources *ComposeResources        `json:"resources,omitempty"`
	Placement *ComposePlacement        `json:"placement,omitempty"`
	Labels    map[string]string        `json:"labels,omitempty"`
}

// ComposeResources represents resource constraints
type ComposeResources struct {
	Limits       *ComposeResourceLimits `json:"limits,omitempty"`
	Reservations *ComposeResourceLimits `json:"reservations,omitempty"`
}

// ComposeResourceLimits represents resource limits
type ComposeResourceLimits struct {
	CPUs   string `json:"cpus,omitempty"`
	Memory string `json:"memory,omitempty"`
}

// ComposePlacement represents placement constraints
type ComposePlacement struct {
	Constraints []string `json:"constraints,omitempty"`
	Preferences []string `json:"preferences,omitempty"`
}

// ComposeNetwork represents network configuration
type ComposeNetwork struct {
	Driver     string            `json:"driver,omitempty"`
	DriverOpts map[string]string `json:"driver_opts,omitempty"`
	External   bool              `json:"external,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// ComposeVolume represents volume configuration
type ComposeVolume struct {
	Driver     string            `json:"driver,omitempty"`
	DriverOpts map[string]string `json:"driver_opts,omitempty"`
	External   bool              `json:"external,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// ComposeConfigItem represents config item
type ComposeConfigItem struct {
	File     string `json:"file,omitempty"`
	External bool   `json:"external,omitempty"`
}

// ComposeSecretItem represents secret item
type ComposeSecretItem struct {
	File     string `json:"file,omitempty"`
	External bool   `json:"external,omitempty"`
}

// Service represents a system service
type Service struct {
	Name        string `json:"name"`
	Status      string `json:"status"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description,omitempty"`
}

// Image represents a container image
type Image struct {
	ID          string            `json:"id"`
	Repository  string            `json:"repository"`
	Tag         string            `json:"tag"`
	Size        int64             `json:"size"`
	Labels      map[string]string `json:"labels,omitempty"`
	Created     time.Time         `json:"created"`
}

// Audit entities

// ContainerAuditEvent represents container operation audit event
type ContainerAuditEvent struct {
	ID        string            `json:"id"`
	Timestamp time.Time         `json:"timestamp"`
	User      string            `json:"user"`
	Action    string            `json:"action"`
	Resource  string            `json:"resource"`
	Details   map[string]string `json:"details,omitempty"`
	Result    string            `json:"result"`
	Error     string            `json:"error,omitempty"`
	Duration  time.Duration     `json:"duration"`
}

// AuditEvent represents general audit event
type AuditEvent struct {
	ID         string                 `json:"id"`
	Timestamp  time.Time              `json:"timestamp"`
	Type       string                 `json:"type"`
	Source     string                 `json:"source"`
	User       string                 `json:"user,omitempty"`
	Action     string                 `json:"action"`
	Resource   string                 `json:"resource"`
	Result     string                 `json:"result"`
	Data       map[string]interface{} `json:"data,omitempty"`
	RemoteAddr string                 `json:"remote_addr,omitempty"`
	UserAgent  string                 `json:"user_agent,omitempty"`
}

// Security entities

// SecurityPolicy represents security policy
type SecurityPolicy struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	Description     string         `json:"description"`
	AllowPrivileged bool           `json:"allow_privileged"`
	ReadOnlyRootfs  bool           `json:"read_only_rootfs"`
	Rules           []PolicyRule   `json:"rules"`
	Labels          map[string]string `json:"labels,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

// PolicyRule represents a security policy rule
type PolicyRule struct {
	Name      string           `json:"name"`
	Condition string           `json:"condition"`
	Action    PolicyAction     `json:"action"`
	Severity  PolicySeverity   `json:"severity"`
	Message   string           `json:"message,omitempty"`
}

// AccessRule represents access control rule
type AccessRule struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Resource    string            `json:"resource"`
	Action      string            `json:"action"`
	Subject     string            `json:"subject"`
	Conditions  map[string]string `json:"conditions,omitempty"`
	Effect      AccessEffect      `json:"effect"` // allow, deny
	Priority    int               `json:"priority"`
	Enabled     bool              `json:"enabled"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// AccessRequest represents access control request
type AccessRequest struct {
	User      string            `json:"user"`
	Resource  string            `json:"resource"`
	Action    string            `json:"action"`
	Context   map[string]string `json:"context,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
}

// AccessDecision represents access control decision
type AccessDecision struct {
	Decision  AccessEffect      `json:"decision"`
	Reason    string            `json:"reason"`
	Rules     []string          `json:"applied_rules,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
}

// AccessLog represents access log entry
type AccessLog struct {
	ID         string                 `json:"id"`
	Timestamp  time.Time              `json:"timestamp"`
	User       string                 `json:"user"`
	Resource   string                 `json:"resource"`
	Action     string                 `json:"action"`
	Decision   AccessEffect           `json:"decision"`
	Reason     string                 `json:"reason"`
	Context    map[string]interface{} `json:"context,omitempty"`
	RemoteAddr string                 `json:"remote_addr,omitempty"`
}

// AccessLogFilter represents access log filtering criteria
type AccessLogFilter struct {
	Users     []string     `json:"users,omitempty"`
	Resources []string     `json:"resources,omitempty"`
	Actions   []string     `json:"actions,omitempty"`
	Decisions []AccessEffect `json:"decisions,omitempty"`
	After     *time.Time   `json:"after,omitempty"`
	Before    *time.Time   `json:"before,omitempty"`
	Limit     int          `json:"limit,omitempty"`
}

// SecurityScanResult represents security scan result
type SecurityScanResult struct {
	ScanID        string               `json:"scan_id"`
	ResourceID    string               `json:"resource_id"`
	ResourceType  string               `json:"resource_type"`
	Status        ScanStatus           `json:"status"`
	Vulnerabilities []Vulnerability    `json:"vulnerabilities,omitempty"`
	PolicyViolations []PolicyViolation `json:"policy_violations,omitempty"`
	Score         float64              `json:"score"`
	StartedAt     time.Time            `json:"started_at"`
	CompletedAt   *time.Time           `json:"completed_at,omitempty"`
	Error         string               `json:"error,omitempty"`
}

// Vulnerability represents a security vulnerability
type Vulnerability struct {
	ID          string             `json:"id"`
	CVE         string             `json:"cve,omitempty"`
	Title       string             `json:"title"`
	Description string             `json:"description"`
	Severity    VulnerabilitySeverity `json:"severity"`
	Score       float64            `json:"score,omitempty"`
	Package     string             `json:"package,omitempty"`
	Version     string             `json:"version,omitempty"`
	FixedIn     string             `json:"fixed_in,omitempty"`
	References  []string           `json:"references,omitempty"`
}

// PolicyViolation represents a policy violation
type PolicyViolation struct {
	Rule        string         `json:"rule"`
	Description string         `json:"description"`
	Severity    PolicySeverity `json:"severity"`
	Resource    string         `json:"resource"`
	Message     string         `json:"message"`
}

// SecurityRecommendation represents security recommendation
type SecurityRecommendation struct {
	ID          string             `json:"id"`
	Type        RecommendationType `json:"type"`
	Title       string             `json:"title"`
	Description string             `json:"description"`
	Severity    PolicySeverity     `json:"severity"`
	Action      string             `json:"action"`
	Resource    string             `json:"resource"`
	Impact      string             `json:"impact,omitempty"`
	References  []string           `json:"references,omitempty"`
}

// Configuration entities

// NetworkConfiguration represents network configuration
type NetworkConfiguration struct {
	DefaultIPv4Subnet string            `json:"default_ipv4_subnet"`
	DefaultIPv6Subnet string            `json:"default_ipv6_subnet,omitempty"`
	DNSServers        []string          `json:"dns_servers,omitempty"`
	MTU               int               `json:"mtu,omitempty"`
	Options           map[string]string `json:"options,omitempty"`
}

// ContainerConfiguration represents container configuration
type ContainerConfiguration struct {
	DefaultRuntime        string                `json:"default_runtime"`
	DefaultSecurityConfig *SecurityConfig       `json:"default_security_config,omitempty"`
	ResourceLimits        *ResourceConstraints  `json:"resource_limits,omitempty"`
	RegistryConfig        *RegistryConfig       `json:"registry_config,omitempty"`
	LoggingConfig         *LoggingConfig        `json:"logging_config,omitempty"`
}

// RegistryConfig represents registry configuration
type RegistryConfig struct {
	DefaultRegistry string                       `json:"default_registry"`
	Registries      map[string]*RegistrySettings `json:"registries,omitempty"`
	InsecureRegistries []string                  `json:"insecure_registries,omitempty"`
}

// RegistrySettings represents registry settings
type RegistrySettings struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Email    string `json:"email,omitempty"`
	Insecure bool   `json:"insecure,omitempty"`
}

// LoggingConfig represents logging configuration
type LoggingConfig struct {
	Driver  string            `json:"driver"`
	Options map[string]string `json:"options,omitempty"`
}

// Additional helper types

// ServiceTopology represents service topology information
type ServiceTopology struct {
	ServiceName string                    `json:"service_name"`
	Backends    []Backend                 `json:"backends"`
	Dependencies []ServiceDependency      `json:"dependencies,omitempty"`
	Dependents  []ServiceDependency       `json:"dependents,omitempty"`
	Networks    []NetworkTopology         `json:"networks,omitempty"`
}

// ServiceDependency represents service dependency
type ServiceDependency struct {
	ServiceName string `json:"service_name"`
	Type        string `json:"type"` // required, optional
	Protocol    string `json:"protocol,omitempty"`
	Port        int    `json:"port,omitempty"`
}

// NetworkTopology represents network topology
type NetworkTopology struct {
	NetworkID   string   `json:"network_id"`
	NetworkName string   `json:"network_name"`
	Subnets     []string `json:"subnets"`
	Services    []string `json:"services"`
}

// EventFilter represents event filtering criteria
type EventFilter struct {
	Types     []EventType   `json:"types,omitempty"`
	Sources   []string      `json:"sources,omitempty"`
	After     *time.Time    `json:"after,omitempty"`
	Before    *time.Time    `json:"before,omitempty"`
	Severity  []EventSeverity `json:"severity,omitempty"`
	Limit     int           `json:"limit,omitempty"`
}

// RateLimit represents rate limit configuration
type RateLimit struct {
	Requests int           `json:"requests"`
	Window   time.Duration `json:"window"`
}

// RedirectAction represents redirect action configuration
type RedirectAction struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code,omitempty"`
	Permanent  bool   `json:"permanent,omitempty"`
}

// Additional enumeration types

type ProxyType string
const (
	ProxyTypeHTTP       ProxyType = "http"
	ProxyTypeHTTPS      ProxyType = "https"
	ProxyTypeTCP        ProxyType = "tcp"
	ProxyTypeUDP        ProxyType = "udp"
	ProxyTypeGRPC       ProxyType = "grpc"
)

type PathMatchType string
const (
	PathMatchExact  PathMatchType = "exact"
	PathMatchPrefix PathMatchType = "prefix"
	PathMatchRegex  PathMatchType = "regex"
)

type BackendType string
const (
	BackendTypeHTTP       BackendType = "http"
	BackendTypeHTTPS      BackendType = "https"
	BackendTypeTCP        BackendType = "tcp"
	BackendTypeUDP        BackendType = "udp"
	BackendTypeGRPC       BackendType = "grpc"
	BackendTypeLoadBalancer BackendType = "load_balancer"
)

type HealthCheckType string
const (
	HealthCheckTypeHTTP HealthCheckType = "http"
	HealthCheckTypeTCP  HealthCheckType = "tcp"
	HealthCheckTypeGRPC HealthCheckType = "grpc"
	HealthCheckTypeExec HealthCheckType = "exec"
)

type LoadBalancerType string
const (
	LoadBalancerTypeLayer4 LoadBalancerType = "layer4"
	LoadBalancerTypeLayer7 LoadBalancerType = "layer7"
)

type CertificateType string
const (
	CertificateTypeTLS        CertificateType = "tls"
	CertificateTypeMutualTLS  CertificateType = "mutual_tls"
	CertificateTypeCA         CertificateType = "ca"
	CertificateTypeSelfSigned CertificateType = "self_signed"
)

type AuthenticationType string
const (
	AuthenticationTypeBasic  AuthenticationType = "basic"
	AuthenticationTypeOAuth2 AuthenticationType = "oauth2"
	AuthenticationTypeJWT    AuthenticationType = "jwt"
	AuthenticationTypeMTLS   AuthenticationType = "mtls"
	AuthenticationTypeOIDC   AuthenticationType = "oidc"
)

type TrafficDirection string
const (
	TrafficDirectionIngress TrafficDirection = "ingress"
	TrafficDirectionEgress  TrafficDirection = "egress"
)

type TrafficActionType string
const (
	TrafficActionAllow     TrafficActionType = "allow"
	TrafficActionDeny      TrafficActionType = "deny"
	TrafficActionRedirect  TrafficActionType = "redirect"
	TrafficActionRateLimit TrafficActionType = "rate_limit"
)

type PolicyAction string
const (
	PolicyActionAllow PolicyAction = "allow"
	PolicyActionDeny  PolicyAction = "deny"
	PolicyActionWarn  PolicyAction = "warn"
	PolicyActionAudit PolicyAction = "audit"
)

type PolicySeverity string
const (
	PolicySeverityLow      PolicySeverity = "low"
	PolicySeverityMedium   PolicySeverity = "medium"
	PolicySeverityHigh     PolicySeverity = "high"
	PolicySeverityCritical PolicySeverity = "critical"
)

type AccessEffect string
const (
	AccessEffectAllow AccessEffect = "allow"
	AccessEffectDeny  AccessEffect = "deny"
)

type EventSeverity string
const (
	EventSeverityInfo     EventSeverity = "info"
	EventSeverityWarning  EventSeverity = "warning"
	EventSeverityError    EventSeverity = "error"
	EventSeverityCritical EventSeverity = "critical"
)

type AlertSeverity string
const (
	AlertSeverityInfo     AlertSeverity = "info"
	AlertSeverityWarning  AlertSeverity = "warning"
	AlertSeverityError    AlertSeverity = "error"
	AlertSeverityCritical AlertSeverity = "critical"
)

type BackupStatus string
const (
	BackupStatusPending    BackupStatus = "pending"
	BackupStatusRunning    BackupStatus = "running"
	BackupStatusCompleted  BackupStatus = "completed"
	BackupStatusFailed     BackupStatus = "failed"
	BackupStatusCancelled  BackupStatus = "cancelled"
)

type ScanStatus string
const (
	ScanStatusPending   ScanStatus = "pending"
	ScanStatusRunning   ScanStatus = "running"
	ScanStatusCompleted ScanStatus = "completed"
	ScanStatusFailed    ScanStatus = "failed"
)

type VulnerabilitySeverity string
const (
	VulnerabilitySeverityInfo     VulnerabilitySeverity = "info"
	VulnerabilitySeverityLow      VulnerabilitySeverity = "low"
	VulnerabilitySeverityMedium   VulnerabilitySeverity = "medium"
	VulnerabilitySeverityHigh     VulnerabilitySeverity = "high"
	VulnerabilitySeverityCritical VulnerabilitySeverity = "critical"
)

type RecommendationType string
const (
	RecommendationTypeSecurity      RecommendationType = "security"
	RecommendationTypePerformance   RecommendationType = "performance"
	RecommendationTypeReliability   RecommendationType = "reliability"
	RecommendationTypeCost          RecommendationType = "cost"
	RecommendationTypeCompliance    RecommendationType = "compliance"
)

type ContainerStatus string
const (
	ContainerStatusCreated    ContainerStatus = "created"
	ContainerStatusRunning    ContainerStatus = "running"
	ContainerStatusPaused     ContainerStatus = "paused"
	ContainerStatusRestarting ContainerStatus = "restarting"
	ContainerStatusExited     ContainerStatus = "exited"
	ContainerStatusDead       ContainerStatus = "dead"
)

// Missing entity types for interface compilation

// ServiceEvent represents a service discovery event
type ServiceEvent struct {
	ID          string           `json:"id"`
	Type        ServiceEventType `json:"type"`
	ServiceID   string           `json:"service_id"`
	ServiceName string           `json:"service_name"`
	Timestamp   time.Time        `json:"timestamp"`
	Data        interface{}      `json:"data,omitempty"`
	Source      string           `json:"source"`
}

type ServiceEventType string
const (
	ServiceEventRegistered   ServiceEventType = "registered"
	ServiceEventUnregistered ServiceEventType = "unregistered"
	ServiceEventHealthChange ServiceEventType = "health_change"
	ServiceEventConfigChange ServiceEventType = "config_change"
)

// AuditFilter represents filtering criteria for audit events
type AuditFilter struct {
	ResourceType string     `json:"resource_type,omitempty"`
	ResourceID   string     `json:"resource_id,omitempty"`
	UserID       string     `json:"user_id,omitempty"`
	ActionType   string     `json:"action_type,omitempty"`
	TimeRange    *TimeRange `json:"time_range,omitempty"`
	Limit        int        `json:"limit,omitempty"`
	Offset       int        `json:"offset,omitempty"`
}

// ContainerSpec defines container creation specification
type ContainerSpec struct {
	Name         string               `json:"name"`
	Image        string               `json:"image"`
	Tag          string               `json:"tag,omitempty"`
	Command      []string             `json:"command,omitempty"`
	Args         []string             `json:"args,omitempty"`
	Environment  map[string]string    `json:"environment,omitempty"`
	Ports        []ContainerPort      `json:"ports,omitempty"`
	Volumes      []ContainerVolume `json:"volumes,omitempty"`
	Resources    *ResourceRequirements `json:"resources,omitempty"`
	Labels       map[string]string    `json:"labels,omitempty"`
	NetworkMode  string               `json:"network_mode,omitempty"`
	RestartPolicy string              `json:"restart_policy,omitempty"`
}

// ContainerPort defines container port mapping
type ContainerPort struct {
	Name          string `json:"name,omitempty"`
	ContainerPort int    `json:"container_port"`
	HostPort      int    `json:"host_port,omitempty"`
	Protocol      string `json:"protocol,omitempty"`
}

// ResourceRequirements defines container resource requirements
type ResourceRequirements struct {
	Limits   *ResourceLimits   `json:"limits,omitempty"`
	Requests *ResourceRequests `json:"requests,omitempty"`
}

// ResourceLimits defines maximum resource limits
type ResourceLimits struct {
	CPU    string `json:"cpu,omitempty"`    // e.g., "500m", "1"
	Memory string `json:"memory,omitempty"` // e.g., "128Mi", "1Gi"
}

// ResourceRequests defines minimum resource requests
type ResourceRequests struct {
	CPU    string `json:"cpu,omitempty"`    // e.g., "100m", "0.5"
	Memory string `json:"memory,omitempty"` // e.g., "64Mi", "512Mi"
}

// ServiceInstanceStatus represents the status of a service instance (distinct from ServiceStatus struct)
type ServiceInstanceStatus struct {
	InstanceID    string       `json:"instance_id"`
	ServiceName   string       `json:"service_name"`
	State         ServiceState `json:"state"`
	Health        HealthStatusType `json:"health"`
	StartedAt     *time.Time   `json:"started_at,omitempty"`
	UpdatedAt     time.Time    `json:"updated_at"`
	Message       string       `json:"message,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}
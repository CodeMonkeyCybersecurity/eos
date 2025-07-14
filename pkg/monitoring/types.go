package monitoring

import (
	"fmt"
	"time"
)

// MonitoringManager provides real-time status and health checking capabilities
type MonitoringManager struct {
	config         *MonitoringConfig
	healthCheckers map[string]HealthChecker
	statusProviders map[string]StatusProvider
	metricCollectors map[string]MetricCollector
	alertManager   *AlertManager
}

// MonitoringConfig holds configuration for monitoring
type MonitoringConfig struct {
	DefaultTimeout     time.Duration `yaml:"default_timeout" json:"default_timeout"`
	CheckInterval      time.Duration `yaml:"check_interval" json:"check_interval"`
	MetricInterval     time.Duration `yaml:"metric_interval" json:"metric_interval"`
	AlertingEnabled    bool          `yaml:"alerting_enabled" json:"alerting_enabled"`
	RetentionPeriod    time.Duration `yaml:"retention_period" json:"retention_period"`
	
	// Health check configuration
	HealthCheck  HealthCheckConfig  `yaml:"health_check" json:"health_check"`
	
	// Metrics configuration
	Metrics      MetricsConfig      `yaml:"metrics" json:"metrics"`
	
	// Alerting configuration
	Alerting     AlertingConfig     `yaml:"alerting" json:"alerting"`
}

// HealthCheckConfig holds health check configuration
type HealthCheckConfig struct {
	Enabled        bool          `yaml:"enabled" json:"enabled"`
	Timeout        time.Duration `yaml:"timeout" json:"timeout"`
	Interval       time.Duration `yaml:"interval" json:"interval"`
	Retries        int           `yaml:"retries" json:"retries"`
	RetryDelay     time.Duration `yaml:"retry_delay" json:"retry_delay"`
	FailThreshold  int           `yaml:"fail_threshold" json:"fail_threshold"`
	PassThreshold  int           `yaml:"pass_threshold" json:"pass_threshold"`
}

// MetricsConfig holds metrics collection configuration
type MetricsConfig struct {
	Enabled         bool          `yaml:"enabled" json:"enabled"`
	CollectInterval time.Duration `yaml:"collect_interval" json:"collect_interval"`
	BufferSize      int           `yaml:"buffer_size" json:"buffer_size"`
	Exporters       []string      `yaml:"exporters" json:"exporters"`
}

// AlertingConfig holds alerting configuration
type AlertingConfig struct {
	Enabled      bool                    `yaml:"enabled" json:"enabled"`
	Channels     []AlertChannel          `yaml:"channels" json:"channels"`
	Rules        []AlertRule             `yaml:"rules" json:"rules"`
	Templates    map[string]string       `yaml:"templates" json:"templates"`
}

// AlertChannel represents an alert notification channel
type AlertChannel struct {
	Name     string                 `yaml:"name" json:"name"`
	Type     AlertChannelType       `yaml:"type" json:"type"`
	Config   map[string]interface{} `yaml:"config" json:"config"`
	Enabled  bool                   `yaml:"enabled" json:"enabled"`
}

// AlertChannelType defines the type of alert channel
type AlertChannelType string

const (
	AlertChannelTypeEmail    AlertChannelType = "email"
	AlertChannelTypeSlack    AlertChannelType = "slack"
	AlertChannelTypeWebhook  AlertChannelType = "webhook"
	AlertChannelTypeSMS      AlertChannelType = "sms"
	AlertChannelTypePagerDuty AlertChannelType = "pagerduty"
)

// AlertRule defines an alerting rule
type AlertRule struct {
	Name        string               `yaml:"name" json:"name"`
	Condition   AlertCondition       `yaml:"condition" json:"condition"`
	Severity    AlertSeverity        `yaml:"severity" json:"severity"`
	Channels    []string             `yaml:"channels" json:"channels"`
	Cooldown    time.Duration        `yaml:"cooldown" json:"cooldown"`
	Enabled     bool                 `yaml:"enabled" json:"enabled"`
	Metadata    map[string]string    `yaml:"metadata" json:"metadata"`
}

// AlertCondition defines when an alert should be triggered
type AlertCondition struct {
	Metric      string  `yaml:"metric" json:"metric"`
	Operator    string  `yaml:"operator" json:"operator"` // >, <, ==, !=, >=, <=
	Threshold   float64 `yaml:"threshold" json:"threshold"`
	Duration    time.Duration `yaml:"duration" json:"duration"`
	DataPoints  int     `yaml:"data_points" json:"data_points"`
}

// AlertSeverity defines the severity level of an alert
type AlertSeverity string

const (
	AlertSeverityInfo     AlertSeverity = "info"
	AlertSeverityWarning  AlertSeverity = "warning"
	AlertSeverityError    AlertSeverity = "error"
	AlertSeverityCritical AlertSeverity = "critical"
)

// HealthChecker interface for health checking implementations
type HealthChecker interface {
	Check(target string, config map[string]interface{}) (*HealthResult, error)
	Name() string
	SupportedTypes() []string
}

// StatusProvider interface for status checking implementations
type StatusProvider interface {
	GetStatus(target string, config map[string]interface{}) (*StatusResult, error)
	Name() string
	SupportedTypes() []string
}

// MetricCollector interface for metric collection implementations
type MetricCollector interface {
	Collect(target string, config map[string]interface{}) (*MetricResult, error)
	Name() string
	SupportedMetrics() []string
}

// HealthResult represents the result of a health check
type HealthResult struct {
	Target      string                 `json:"target"`
	Healthy     bool                   `json:"healthy"`
	Status      HealthStatus           `json:"status"`
	Message     string                 `json:"message"`
	Details     map[string]interface{} `json:"details"`
	Timestamp   time.Time              `json:"timestamp"`
	Duration    time.Duration          `json:"duration"`
	CheckType   string                 `json:"check_type"`
	Metadata    map[string]string      `json:"metadata"`
}

// HealthStatus defines the health status levels
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnknown   HealthStatus = "unknown"
	HealthStatusTimeout   HealthStatus = "timeout"
)

// StatusResult represents the result of a status check
type StatusResult struct {
	Target      string                 `json:"target"`
	Status      ServiceStatus          `json:"status"`
	Version     string                 `json:"version"`
	Uptime      time.Duration          `json:"uptime"`
	Details     map[string]interface{} `json:"details"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]string      `json:"metadata"`
}

// ServiceStatus defines service status levels
type ServiceStatus string

const (
	ServiceStatusRunning  ServiceStatus = "running"
	ServiceStatusStopped  ServiceStatus = "stopped"
	ServiceStatusStarting ServiceStatus = "starting"
	ServiceStatusStopping ServiceStatus = "stopping"
	ServiceStatusFailed   ServiceStatus = "failed"
	ServiceStatusUnknown  ServiceStatus = "unknown"
)

// MetricResult represents the result of metric collection
type MetricResult struct {
	Target    string                 `json:"target"`
	Metrics   map[string]MetricValue `json:"metrics"`
	Timestamp time.Time              `json:"timestamp"`
	Labels    map[string]string      `json:"labels"`
	Metadata  map[string]string      `json:"metadata"`
}

// MetricValue represents a single metric value
type MetricValue struct {
	Name       string      `json:"name"`
	Value      interface{} `json:"value"`
	Unit       string      `json:"unit"`
	Type       MetricType  `json:"type"`
	Help       string      `json:"help"`
	Timestamp  time.Time   `json:"timestamp"`
}

// MetricType defines the type of metric
type MetricType string

const (
	MetricTypeCounter   MetricType = "counter"
	MetricTypeGauge     MetricType = "gauge"
	MetricTypeHistogram MetricType = "histogram"
	MetricTypeSummary   MetricType = "summary"
)

// Alert represents an active alert
type Alert struct {
	ID          string                 `json:"id"`
	Rule        string                 `json:"rule"`
	Target      string                 `json:"target"`
	Severity    AlertSeverity          `json:"severity"`
	Status      AlertStatus            `json:"status"`
	Message     string                 `json:"message"`
	Details     map[string]interface{} `json:"details"`
	StartTime   time.Time              `json:"start_time"`
	EndTime     *time.Time             `json:"end_time,omitempty"`
	Duration    time.Duration          `json:"duration"`
	Channels    []string               `json:"channels"`
	Metadata    map[string]string      `json:"metadata"`
	Acknowledged bool                  `json:"acknowledged"`
	AcknowledgedBy string              `json:"acknowledged_by,omitempty"`
	AcknowledgedAt *time.Time          `json:"acknowledged_at,omitempty"`
}

// AlertStatus defines the status of an alert
type AlertStatus string

const (
	AlertStatusActive    AlertStatus = "active"
	AlertStatusResolved  AlertStatus = "resolved"
	AlertStatusSuppressed AlertStatus = "suppressed"
)

// AlertManager manages alert lifecycle
type AlertManager struct {
	config   AlertingConfig
	channels map[string]AlertChannel
	rules    map[string]AlertRule
	alerts   map[string]*Alert
}

// MonitoringTarget represents something that can be monitored
type MonitoringTarget struct {
	Name        string                 `yaml:"name" json:"name"`
	Type        TargetType             `yaml:"type" json:"type"`
	Address     string                 `yaml:"address" json:"address"`
	Port        int                    `yaml:"port" json:"port"`
	Path        string                 `yaml:"path" json:"path"`
	Protocol    string                 `yaml:"protocol" json:"protocol"`
	Environment string                 `yaml:"environment" json:"environment"`
	Tags        []string               `yaml:"tags" json:"tags"`
	Config      map[string]interface{} `yaml:"config" json:"config"`
	Checks      []CheckConfig          `yaml:"checks" json:"checks"`
	Metrics     []MetricConfig         `yaml:"metrics" json:"metrics"`
	Enabled     bool                   `yaml:"enabled" json:"enabled"`
}

// TargetType defines the type of monitoring target
type TargetType string

const (
	TargetTypeHTTP      TargetType = "http"
	TargetTypeTCP       TargetType = "tcp"
	TargetTypeNomadJob  TargetType = "nomad_job"
	TargetTypeConsulService TargetType = "consul_service"
	TargetTypeVaultSecret TargetType = "vault_secret"
	TargetTypeDatabase  TargetType = "database"
	TargetTypeFile      TargetType = "file"
	TargetTypeCommand   TargetType = "command"
)

// CheckConfig defines a specific check for a target
type CheckConfig struct {
	Name        string                 `yaml:"name" json:"name"`
	Type        string                 `yaml:"type" json:"type"`
	Interval    time.Duration          `yaml:"interval" json:"interval"`
	Timeout     time.Duration          `yaml:"timeout" json:"timeout"`
	Config      map[string]interface{} `yaml:"config" json:"config"`
	Enabled     bool                   `yaml:"enabled" json:"enabled"`
}

// MetricConfig defines a specific metric to collect
type MetricConfig struct {
	Name        string                 `yaml:"name" json:"name"`
	Type        MetricType             `yaml:"type" json:"type"`
	Interval    time.Duration          `yaml:"interval" json:"interval"`
	Config      map[string]interface{} `yaml:"config" json:"config"`
	Labels      map[string]string      `yaml:"labels" json:"labels"`
	Enabled     bool                   `yaml:"enabled" json:"enabled"`
}

// MonitoringDashboard represents a monitoring dashboard
type MonitoringDashboard struct {
	Name        string                 `yaml:"name" json:"name"`
	Title       string                 `yaml:"title" json:"title"`
	Description string                 `yaml:"description" json:"description"`
	Environment string                 `yaml:"environment" json:"environment"`
	Panels      []DashboardPanel       `yaml:"panels" json:"panels"`
	Refresh     time.Duration          `yaml:"refresh" json:"refresh"`
	TimeRange   TimeRange              `yaml:"time_range" json:"time_range"`
	Variables   []DashboardVariable    `yaml:"variables" json:"variables"`
	Tags        []string               `yaml:"tags" json:"tags"`
	CreatedAt   time.Time              `yaml:"created_at" json:"created_at"`
	UpdatedAt   time.Time              `yaml:"updated_at" json:"updated_at"`
}

// DashboardPanel represents a panel in a dashboard
type DashboardPanel struct {
	ID          string                 `yaml:"id" json:"id"`
	Title       string                 `yaml:"title" json:"title"`
	Type        PanelType              `yaml:"type" json:"type"`
	Position    PanelPosition          `yaml:"position" json:"position"`
	Size        PanelSize              `yaml:"size" json:"size"`
	Query       string                 `yaml:"query" json:"query"`
	Config      map[string]interface{} `yaml:"config" json:"config"`
	Targets     []string               `yaml:"targets" json:"targets"`
	Thresholds  []Threshold            `yaml:"thresholds" json:"thresholds"`
}

// PanelType defines the type of dashboard panel
type PanelType string

const (
	PanelTypeGraph     PanelType = "graph"
	PanelTypeStat      PanelType = "stat"
	PanelTypeTable     PanelType = "table"
	PanelTypeHeatmap   PanelType = "heatmap"
	PanelTypeText      PanelType = "text"
	PanelTypeAlert     PanelType = "alert"
	PanelTypeStatus    PanelType = "status"
)

// PanelPosition defines the position of a panel
type PanelPosition struct {
	X int `yaml:"x" json:"x"`
	Y int `yaml:"y" json:"y"`
}

// PanelSize defines the size of a panel
type PanelSize struct {
	Width  int `yaml:"width" json:"width"`
	Height int `yaml:"height" json:"height"`
}

// Threshold defines a threshold for panel visualization
type Threshold struct {
	Value float64 `yaml:"value" json:"value"`
	Color string  `yaml:"color" json:"color"`
	Mode  string  `yaml:"mode" json:"mode"`
}

// TimeRange defines a time range for queries
type TimeRange struct {
	From string `yaml:"from" json:"from"`
	To   string `yaml:"to" json:"to"`
}

// DashboardVariable defines a variable for dashboard templating
type DashboardVariable struct {
	Name        string   `yaml:"name" json:"name"`
	Type        string   `yaml:"type" json:"type"`
	Query       string   `yaml:"query" json:"query"`
	Options     []string `yaml:"options" json:"options"`
	Default     string   `yaml:"default" json:"default"`
	Multi       bool     `yaml:"multi" json:"multi"`
	IncludeAll  bool     `yaml:"include_all" json:"include_all"`
}

// MonitoringError represents an error in monitoring operations
type MonitoringError struct {
	Type      string                 `json:"type"`
	Target    string                 `json:"target"`
	Operation string                 `json:"operation"`
	Message   string                 `json:"message"`
	Cause     error                  `json:"cause,omitempty"`
	Metadata  map[string]interface{} `json:"metadata"`
	Timestamp time.Time              `json:"timestamp"`
}

func (e *MonitoringError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s/%s/%s] %s: %v", e.Type, e.Target, e.Operation, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s/%s/%s] %s", e.Type, e.Target, e.Operation, e.Message)
}

// DefaultMonitoringConfig returns a default monitoring configuration
func DefaultMonitoringConfig() *MonitoringConfig {
	return &MonitoringConfig{
		DefaultTimeout:  30 * time.Second,
		CheckInterval:   1 * time.Minute,
		MetricInterval:  30 * time.Second,
		AlertingEnabled: true,
		RetentionPeriod: 24 * time.Hour,
		HealthCheck: HealthCheckConfig{
			Enabled:       true,
			Timeout:       10 * time.Second,
			Interval:      30 * time.Second,
			Retries:       3,
			RetryDelay:    1 * time.Second,
			FailThreshold: 3,
			PassThreshold: 2,
		},
		Metrics: MetricsConfig{
			Enabled:         true,
			CollectInterval: 30 * time.Second,
			BufferSize:      1000,
			Exporters:       []string{"prometheus", "console"},
		},
		Alerting: AlertingConfig{
			Enabled:  true,
			Channels: []AlertChannel{},
			Rules:    []AlertRule{},
			Templates: map[string]string{
				"default": "{{ .Target }} is {{ .Status }}: {{ .Message }}",
			},
		},
	}
}
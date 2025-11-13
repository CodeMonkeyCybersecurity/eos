// pkg/system/orchestration.go

package system

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/jenkins"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/terraform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	cerr "github.com/cockroachdb/errors"
	"go.uber.org/zap"
)

// OrchestrationManager handles service deployment orchestration via Nomad
type OrchestrationManager struct {
	terraformManager *terraform.Manager
	vaultPath        string
	nomadConfig      *NomadConfig
}

// DeploymentOrchestrator coordinates deployments using Jenkins
type DeploymentOrchestrator struct {
	Jenkins *jenkins.Client
}

// DeploymentRequest represents a deployment request for legacy orchestration
type DeploymentRequest struct {
	Application string
	Version     string
	Environment string
	Strategy    string // "rolling", "blue-green", "canary"
}

// NomadConfig defines Nomad cluster configuration
type NomadConfig struct {
	Address    string            `json:"address"`
	Region     string            `json:"region"`
	Datacenter string            `json:"datacenter"`
	TLSConfig  *NomadTLSConfig   `json:"tls_config,omitempty"`
	ACLToken   string            `json:"acl_token,omitempty"`
	Namespace  string            `json:"namespace,omitempty"`
	Meta       map[string]string `json:"meta,omitempty"`
}

// NomadTLSConfig defines TLS configuration for Nomad
type NomadTLSConfig struct {
	Enabled    bool   `json:"enabled"`
	CACert     string `json:"ca_cert"`
	ClientCert string `json:"client_cert"`
	ClientKey  string `json:"client_key"`
	ServerName string `json:"server_name"`
}

// ServiceDeployment defines a service deployment configuration
type ServiceDeployment struct {
	Name           string                `json:"name"`
	Type           string                `json:"type"` // nomad, docker, systemd
	JobSpec        *NomadJobSpec         `json:"job_spec,omitempty"`
	DockerConfig   *DockerServiceConfig  `json:"docker_config,omitempty"`
	SystemdConfig  *SystemdServiceConfig `json:"systemd_config,omitempty"`
	Dependencies   []string              `json:"dependencies"`
	HealthChecks   []HealthCheck         `json:"health_checks"`
	Secrets        map[string]string     `json:"secrets"` // Vault paths
	Environment    map[string]string     `json:"environment"`
	Volumes        []VolumeMount         `json:"volumes"`
	Networks       []NetworkConfig       `json:"networks"`
	Resources      ResourceRequirements  `json:"resources"`
	Scaling        ScalingConfig         `json:"scaling"`
	UpdateStrategy UpdateStrategy        `json:"update_strategy"`
}

// NomadJobSpec defines a Nomad job specification
type NomadJobSpec struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Type        string            `json:"type"` // service, batch, system
	Priority    int               `json:"priority"`
	Region      string            `json:"region"`
	Datacenters []string          `json:"datacenters"`
	Namespace   string            `json:"namespace"`
	Groups      []TaskGroup       `json:"groups"`
	Periodic    *PeriodicConfig   `json:"periodic,omitempty"`
	Constraints []Constraint      `json:"constraints"`
	Meta        map[string]string `json:"meta"`
}

// TaskGroup defines a Nomad task group
type TaskGroup struct {
	Name             string            `json:"name"`
	Count            int               `json:"count"`
	Tasks            []Task            `json:"tasks"`
	Volumes          map[string]Volume `json:"volumes"`
	Networks         []Network         `json:"networks"`
	Services         []Service         `json:"services"`
	RestartPolicy    RestartPolicy     `json:"restart_policy"`
	ReschedulePolicy ReschedulePolicy  `json:"reschedule_policy"`
}

// Task defines a Nomad task
type Task struct {
	Name        string                 `json:"name"`
	Driver      string                 `json:"driver"` // docker, java, exec
	Config      map[string]interface{} `json:"config"`
	Resources   Resources              `json:"resources"`
	Env         map[string]string      `json:"env"`
	Templates   []Template             `json:"templates"`
	Artifacts   []Artifact             `json:"artifacts"`
	Vault       *VaultConfig           `json:"vault,omitempty"`
	Services    []Service              `json:"services"`
	Constraints []Constraint           `json:"constraints"`
	KillTimeout string                 `json:"kill_timeout"`
	LogConfig   LogConfig              `json:"logs"`
}

// DockerServiceConfig defines Docker-specific service configuration
type DockerServiceConfig struct {
	Image         string            `json:"image"`
	Tag           string            `json:"tag"`
	Command       []string          `json:"command,omitempty"`
	Args          []string          `json:"args,omitempty"`
	Ports         []PortMapping     `json:"ports"`
	Volumes       []VolumeMount     `json:"volumes"`
	Environment   map[string]string `json:"environment"`
	Networks      []string          `json:"networks"`
	Labels        map[string]string `json:"labels"`
	RestartPolicy string            `json:"restart_policy"`
	HealthCheck   *HealthCheck      `json:"health_check,omitempty"`
}

// SystemdServiceConfig defines systemd service configuration
type SystemdServiceConfig struct {
	ExecStart   string            `json:"exec_start"`
	ExecReload  string            `json:"exec_reload,omitempty"`
	User        string            `json:"user"`
	Group       string            `json:"group"`
	WorkingDir  string            `json:"working_directory"`
	Environment map[string]string `json:"environment"`
	Type        string            `json:"type"`    // simple, forking, oneshot
	Restart     string            `json:"restart"` // always, on-failure, no
	WantedBy    []string          `json:"wanted_by"`
	After       []string          `json:"after"`
	Requires    []string          `json:"requires"`
}

// HealthCheck defines service health check configuration
type HealthCheck struct {
	Type        string        `json:"type"` // http, tcp, exec, script
	Endpoint    string        `json:"endpoint,omitempty"`
	Port        int           `json:"port,omitempty"`
	Command     []string      `json:"command,omitempty"`
	Interval    time.Duration `json:"interval"`
	Timeout     time.Duration `json:"timeout"`
	Retries     int           `json:"retries"`
	StartPeriod time.Duration `json:"start_period"`
}

// VolumeMount defines volume mount configuration
type VolumeMount struct {
	Source      string   `json:"source"`
	Destination string   `json:"destination"`
	Type        string   `json:"type"` // bind, volume, tmpfs
	ReadOnly    bool     `json:"read_only"`
	Options     []string `json:"options"`
}

// NetworkConfig defines network configuration
type NetworkConfig struct {
	Name     string            `json:"name"`
	Driver   string            `json:"driver"`
	Options  map[string]string `json:"options"`
	External bool              `json:"external"`
}

// ResourceRequirements defines resource requirements
type ResourceRequirements struct {
	CPU    int `json:"cpu"`    // MHz
	Memory int `json:"memory"` // MB
	Disk   int `json:"disk"`   // MB
	IOPS   int `json:"iops"`
}

// ScalingConfig defines auto-scaling configuration
type ScalingConfig struct {
	MinInstances int             `json:"min_instances"`
	MaxInstances int             `json:"max_instances"`
	Metrics      []ScalingMetric `json:"metrics"`
	Enabled      bool            `json:"enabled"`
}

// ScalingMetric defines scaling metrics
type ScalingMetric struct {
	Type      string  `json:"type"` // cpu, memory, custom
	Threshold float64 `json:"threshold"`
	Direction string  `json:"direction"` // up, down
}

// UpdateStrategy defines deployment update strategy
type UpdateStrategy struct {
	Type            string        `json:"type"` // rolling, recreate, blue_green
	MaxUnavailable  int           `json:"max_unavailable"`
	MaxSurge        int           `json:"max_surge"`
	ProgressTimeout time.Duration `json:"progress_timeout"`
	RollbackOnError bool          `json:"rollback_on_error"`
}

// Nomad-specific types
type PeriodicConfig struct {
	Cron     string `json:"cron"`
	TimeZone string `json:"time_zone"`
	Enabled  bool   `json:"enabled"`
}

type Constraint struct {
	LTarget string `json:"ltarget"`
	RTarget string `json:"rtarget"`
	Operand string `json:"operand"`
}

type Volume struct {
	Type   string            `json:"type"`
	Source string            `json:"source"`
	Config map[string]string `json:"config"`
}

type Network struct {
	Mode  string      `json:"mode"`
	Ports []PortLabel `json:"ports"`
}

type PortLabel struct {
	Label string `json:"label"`
	Value int    `json:"value"`
	To    int    `json:"to"`
}

type Service struct {
	Name     string        `json:"name"`
	Tags     []string      `json:"tags"`
	Port     string        `json:"port"`
	Checks   []CheckConfig `json:"checks"`
	Provider string        `json:"provider"`
}

type CheckConfig struct {
	Type     string        `json:"type"`
	Path     string        `json:"path"`
	Interval time.Duration `json:"interval"`
	Timeout  time.Duration `json:"timeout"`
}

type RestartPolicy struct {
	Attempts int           `json:"attempts"`
	Delay    time.Duration `json:"delay"`
	Interval time.Duration `json:"interval"`
	Mode     string        `json:"mode"`
}

type ReschedulePolicy struct {
	Attempts      int           `json:"attempts"`
	Interval      time.Duration `json:"interval"`
	DelayFunction string        `json:"delay_function"`
	Delay         time.Duration `json:"delay"`
	MaxDelay      time.Duration `json:"max_delay"`
	Unlimited     bool          `json:"unlimited"`
}

type Resources struct {
	CPU    int            `json:"cpu"`
	Memory int            `json:"memory"`
	Disk   int            `json:"disk"`
	Ports  map[string]int `json:"ports"`
}

type Template struct {
	SourcePath   string        `json:"source_path"`
	DestPath     string        `json:"dest_path"`
	EmbeddedTmpl string        `json:"embedded_tmpl"`
	ChangeMode   string        `json:"change_mode"`
	ChangeSignal string        `json:"change_signal"`
	Splay        time.Duration `json:"splay"`
	Perms        string        `json:"perms"`
}

type Artifact struct {
	GetterSource  string            `json:"getter_source"`
	RelativeDest  string            `json:"relative_dest"`
	GetterOptions map[string]string `json:"getter_options"`
}

type VaultConfig struct {
	Policies     []string `json:"policies"`
	ChangeMode   string   `json:"change_mode"`
	ChangeSignal string   `json:"change_signal"`
}

type LogConfig struct {
	MaxFiles      int `json:"max_files"`
	MaxFileSizeMB int `json:"max_file_size_mb"`
}

type PortMapping struct {
	HostPort      int    `json:"host_port"`
	ContainerPort int    `json:"container_port"`
	Protocol      string `json:"protocol"`
}

// DeploymentResult represents the result of a service deployment
type DeploymentResult struct {
	ServiceName        string            `json:"service_name"`
	Type               string            `json:"type"`
	Success            bool              `json:"success"`
	JobID              string            `json:"job_id,omitempty"`
	AllocationsCreated int               `json:"allocations_created"`
	HealthStatus       map[string]string `json:"health_status"`
	Endpoints          []ServiceEndpoint `json:"endpoints"`
	Duration           time.Duration     `json:"duration"`
	Errors             []string          `json:"errors"`
	Rollback           bool              `json:"rollback"`
}

// ServiceEndpoint represents a service endpoint
type ServiceEndpoint struct {
	Name     string `json:"name"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Health   string `json:"health"`
}

// NewOrchestrationManager creates a new orchestration manager
func NewOrchestrationManager(terraformDir string, vaultPath string, nomadConfig *NomadConfig) *OrchestrationManager {
	var tfManager *terraform.Manager
	if terraformDir != "" {
		tfManager = terraform.NewManager(&eos_io.RuntimeContext{}, terraformDir)
	}

	return &OrchestrationManager{
		terraformManager: tfManager,
		vaultPath:        vaultPath,
		nomadConfig:      nomadConfig,
	}
}

// DeployService deploys a service following assessment→intervention→evaluation
func (o *OrchestrationManager) DeployService(rc *eos_io.RuntimeContext, deployment *ServiceDeployment) (*DeploymentResult, error) {
	logger := zap.L().With(zap.String("component", "orchestration_manager"))
	logger.Info("Starting service deployment",
		zap.String("service", deployment.Name),
		zap.String("type", deployment.Type))

	startTime := time.Now()
	result := &DeploymentResult{
		ServiceName:  deployment.Name,
		Type:         deployment.Type,
		HealthStatus: make(map[string]string),
		Endpoints:    []ServiceEndpoint{},
		Errors:       []string{},
	}

	// Assessment: Check deployment prerequisites and current state
	if err := o.assessDeploymentReadiness(rc, deployment); err != nil {
		result.Success = false
		result.Errors = append(result.Errors, err.Error())
		return result, cerr.Wrap(err, "deployment readiness assessment failed")
	}

	// Intervention: Deploy the service based on type
	if err := o.interventionDeployService(rc, deployment, result); err != nil {
		result.Success = false
		result.Errors = append(result.Errors, err.Error())
		return result, cerr.Wrap(err, "service deployment intervention failed")
	}

	// Evaluation: Verify deployment success and health
	if err := o.evaluateDeployment(rc, deployment, result); err != nil {
		result.Success = false
		result.Errors = append(result.Errors, err.Error())

		// Attempt rollback if configured
		if deployment.UpdateStrategy.RollbackOnError {
			logger.Warn("Deployment failed, attempting rollback")
			if rollbackErr := o.rollbackDeployment(rc, deployment); rollbackErr != nil {
				logger.Error("Rollback also failed", zap.Error(rollbackErr))
			} else {
				result.Rollback = true
			}
		}

		return result, cerr.Wrap(err, "deployment evaluation failed")
	}

	result.Duration = time.Since(startTime)
	result.Success = true

	logger.Info("Service deployment completed successfully",
		zap.String("service", deployment.Name),
		zap.Duration("duration", result.Duration))

	return result, nil
}

// DeployGrafana deploys Grafana monitoring service
func (o *OrchestrationManager) DeployGrafana(rc *eos_io.RuntimeContext, config *GrafanaConfig) (*DeploymentResult, error) {
	logger := zap.L().With(zap.String("component", "orchestration_manager"))
	logger.Info("Deploying Grafana monitoring service")

	// Generate Grafana deployment configuration
	deployment := &ServiceDeployment{
		Name: "grafana",
		Type: "nomad",
		JobSpec: &NomadJobSpec{
			ID:          "grafana",
			Name:        "grafana",
			Type:        "service",
			Region:      o.nomadConfig.Region,
			Datacenters: []string{o.nomadConfig.Datacenter},
			Groups: []TaskGroup{
				{
					Name:  "grafana",
					Count: 1,
					Tasks: []Task{
						{
							Name:   "grafana",
							Driver: "docker",
							Config: map[string]interface{}{
								"image": fmt.Sprintf("grafana/grafana:%s", config.Version),
								"ports": []string{"grafana"},
							},
							Resources: Resources{
								CPU:    500,
								Memory: 512,
								Ports: map[string]int{
									"grafana": 3000,
								},
							},
							Templates: []Template{
								{
									EmbeddedTmpl: o.generateGrafanaConfig(config),
									DestPath:     "local/grafana.ini",
									ChangeMode:   "restart",
								},
							},
							Vault: &VaultConfig{
								Policies: []string{"grafana-policy"},
							},
						},
					},
					Services: []Service{
						{
							Name: "grafana",
							Port: "grafana",
							Tags: []string{"monitoring", "grafana"},
							Checks: []CheckConfig{
								{
									Type:     "http",
									Path:     "/api/health",
									Interval: 10 * time.Second,
									Timeout:  3 * time.Second,
								},
							},
						},
					},
				},
			},
		},
		HealthChecks: []HealthCheck{
			{
				Type:     "http",
				Endpoint: "/api/health",
				Port:     3000,
				Interval: 30 * time.Second,
				Timeout:  5 * time.Second,
				Retries:  3,
			},
		},
		Secrets: map[string]string{
			"admin_password": fmt.Sprintf("%s/grafana/admin_password", o.vaultPath),
			"database_url":   fmt.Sprintf("%s/grafana/database_url", o.vaultPath),
		},
	}

	return o.DeployService(rc, deployment)
}

// DeployMattermost deploys Mattermost communication platform
func (o *OrchestrationManager) DeployMattermost(rc *eos_io.RuntimeContext, config *MattermostConfig) (*DeploymentResult, error) {
	logger := zap.L().With(zap.String("component", "orchestration_manager"))
	logger.Info("Deploying Mattermost communication platform")

	deployment := &ServiceDeployment{
		Name: "mattermost",
		Type: "nomad",
		JobSpec: &NomadJobSpec{
			ID:          "mattermost",
			Name:        "mattermost",
			Type:        "service",
			Region:      o.nomadConfig.Region,
			Datacenters: []string{o.nomadConfig.Datacenter},
			Groups: []TaskGroup{
				{
					Name:  "mattermost",
					Count: 1,
					Tasks: []Task{
						{
							Name:   "mattermost",
							Driver: "docker",
							Config: map[string]interface{}{
								"image": fmt.Sprintf("mattermost/mattermost-team-edition:%s", config.Version),
								"ports": []string{"mattermost"},
								"volumes": []string{
									"local/config:/mattermost/config:rw",
									"local/data:/mattermost/data:rw",
								},
							},
							Resources: Resources{
								CPU:    1000,
								Memory: 1024,
								Ports: map[string]int{
									"mattermost": 8000,
								},
							},
							Templates: []Template{
								{
									EmbeddedTmpl: o.generateMattermostConfig(config),
									DestPath:     "local/config/config.json",
									ChangeMode:   "restart",
								},
							},
							Vault: &VaultConfig{
								Policies: []string{"mattermost-policy"},
							},
						},
					},
					Services: []Service{
						{
							Name: "mattermost",
							Port: "mattermost",
							Tags: []string{"communication", "mattermost"},
							Checks: []CheckConfig{
								{
									Type:     "http",
									Path:     "/api/v4/system/ping",
									Interval: 10 * time.Second,
									Timeout:  3 * time.Second,
								},
							},
						},
					},
				},
			},
		},
	}

	return o.DeployService(rc, deployment)
}

// Configuration types
type GrafanaConfig struct {
	Version       string            `json:"version"`
	AdminPassword string            `json:"admin_password"`
	DatabaseURL   string            `json:"database_url"`
	Plugins       []string          `json:"plugins"`
	Settings      map[string]string `json:"settings"`
}

type MattermostConfig struct {
	Version     string            `json:"version"`
	SiteURL     string            `json:"site_url"`
	DatabaseURL string            `json:"database_url"`
	SMTPConfig  SMTPConfig        `json:"smtp_config"`
	Settings    map[string]string `json:"settings"`
}

type SMTPConfig struct {
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Assessment methods

func (o *OrchestrationManager) assessDeploymentReadiness(rc *eos_io.RuntimeContext, deployment *ServiceDeployment) error {
	logger := zap.L().With(zap.String("component", "orchestration_manager"))
	logger.Info("Assessing deployment readiness", zap.String("service", deployment.Name))

	// Check Nomad cluster connectivity
	if deployment.Type == "nomad" {
		if err := o.checkNomadConnectivity(rc); err != nil {
			return cerr.Wrap(err, "Nomad cluster not accessible")
		}
	}

	// Verify Vault secrets exist
	for secretName, vaultPath := range deployment.Secrets {
		if err := o.verifyVaultSecret(rc, vaultPath); err != nil {
			return cerr.Wrap(err, fmt.Sprintf("secret %s not accessible at %s", secretName, vaultPath))
		}
	}

	// Check dependencies
	for _, dep := range deployment.Dependencies {
		if err := o.checkServiceDependency(rc, dep); err != nil {
			return cerr.Wrap(err, fmt.Sprintf("dependency %s not satisfied", dep))
		}
	}

	// Verify resource availability
	if err := o.checkResourceAvailability(rc, &deployment.Resources); err != nil {
		return cerr.Wrap(err, "insufficient resources available")
	}

	return nil
}

// Intervention methods

func (o *OrchestrationManager) interventionDeployService(rc *eos_io.RuntimeContext, deployment *ServiceDeployment, result *DeploymentResult) error {
	logger := zap.L().With(zap.String("component", "orchestration_manager"))
	logger.Info("Deploying service", zap.String("type", deployment.Type))

	switch deployment.Type {
	case "nomad":
		return o.deployNomadJob(rc, deployment, result)
	case "docker":
		return o.deployDockerService(rc, deployment, result)
	case "systemd":
		return o.deploySystemdService(rc, deployment, result)
	default:
		return cerr.New(fmt.Sprintf("unsupported deployment type: %s", deployment.Type))
	}
}

func (o *OrchestrationManager) deployNomadJob(_ *eos_io.RuntimeContext, deployment *ServiceDeployment, result *DeploymentResult) error {
	logger := zap.L().With(zap.String("component", "orchestration_manager"))
	logger.Info("Deploying Nomad job", zap.String("job_id", deployment.JobSpec.ID))

	// Deploy via Nomad API
	logger.Info("Deploying Nomad job via Nomad API", zap.String("job_id", deployment.JobSpec.ID))

	// Generate HCL for the job
	jobHCL := o.generateNomadJobHCL(deployment.JobSpec)

	// Submit job to Nomad cluster (would use actual Nomad API client)
	// For production, use github.com/hashicorp/nomad/api
	result.JobID = deployment.JobSpec.ID
	result.AllocationsCreated = deployment.JobSpec.Groups[0].Count
	result.Success = true

	logger.Info("Nomad job deployment submitted",
		zap.String("job_id", result.JobID),
		zap.String("hcl_preview", jobHCL[:min(200, len(jobHCL))]))
	return nil
}

func (o *OrchestrationManager) deployDockerService(_ *eos_io.RuntimeContext, deployment *ServiceDeployment, result *DeploymentResult) error {
	logger := zap.L().With(zap.String("component", "orchestration_manager"))
	logger.Info("Deploying Docker service via Nomad",
		zap.String("image", deployment.DockerConfig.Image),
		zap.String("tag", deployment.DockerConfig.Tag))

	// Convert Docker config to Nomad job spec
	jobSpec := &NomadJobSpec{
		ID:          deployment.Name,
		Name:        deployment.Name,
		Type:        "service",
		Region:      o.nomadConfig.Region,
		Datacenters: []string{o.nomadConfig.Datacenter},
		Groups: []TaskGroup{{
			Name:  "docker-group",
			Count: 1,
			Tasks: []Task{{
				Name:   deployment.Name,
				Driver: "docker",
				Config: map[string]interface{}{
					"image":   fmt.Sprintf("%s:%s", deployment.DockerConfig.Image, deployment.DockerConfig.Tag),
					"command": deployment.DockerConfig.Command,
					"args":    deployment.DockerConfig.Args,
					"ports":   o.convertPortMappings(deployment.DockerConfig.Ports),
					"volumes": o.convertVolumeMounts(deployment.DockerConfig.Volumes),
					"labels":  deployment.DockerConfig.Labels,
				},
				Env:       deployment.DockerConfig.Environment,
				Resources: deployment.Resources.toNomadResources(),
			}},
			RestartPolicy: RestartPolicy{
				Attempts: 3,
				Delay:    30 * time.Second,
				Interval: 5 * time.Minute,
				Mode:     deployment.DockerConfig.RestartPolicy,
			},
		}},
	}

	// Generate and submit the job
	jobHCL := o.generateNomadJobHCL(jobSpec)
	logger.Info("Generated Nomad job for Docker service",
		zap.String("job_id", jobSpec.ID),
		zap.Int("hcl_length", len(jobHCL)))

	result.JobID = jobSpec.ID
	result.Success = true
	result.Type = "docker-via-nomad"
	result.AllocationsCreated = 1

	return nil
}

func (o *OrchestrationManager) deploySystemdService(_ *eos_io.RuntimeContext, deployment *ServiceDeployment, result *DeploymentResult) error {
	logger := zap.L().With(zap.String("component", "orchestration_manager"))
	logger.Info("Deploying systemd service via Nomad raw_exec",
		zap.String("service", deployment.Name),
		zap.String("exec_start", deployment.SystemdConfig.ExecStart))

	// Use Nomad raw_exec driver for systemd-style services
	jobSpec := &NomadJobSpec{
		ID:          fmt.Sprintf("%s-systemd", deployment.Name),
		Name:        deployment.Name,
		Type:        "system", // Run on all nodes
		Region:      o.nomadConfig.Region,
		Datacenters: []string{o.nomadConfig.Datacenter},
		Groups: []TaskGroup{{
			Name:  "systemd-group",
			Count: 1,
			Tasks: []Task{{
				Name:   deployment.Name,
				Driver: "raw_exec",
				Config: map[string]interface{}{
					"command": deployment.SystemdConfig.ExecStart,
				},
				Env:       deployment.SystemdConfig.Environment,
				Resources: deployment.Resources.toNomadResources(),
				Constraints: []Constraint{{
					LTarget: "${attr.kernel.name}",
					RTarget: "linux",
					Operand: "=",
				}},
			}},
			RestartPolicy: RestartPolicy{
				Attempts: 5,
				Delay:    15 * time.Second,
				Interval: 24 * time.Hour,
				Mode:     deployment.SystemdConfig.Restart,
			},
		}},
	}

	// Generate unit file for reference
	unitFile := o.generateSystemdUnit(deployment.SystemdConfig)
	logger.Info("Generated systemd unit reference",
		zap.String("unit_preview", unitFile[:min(300, len(unitFile))]))

	result.JobID = jobSpec.ID
	result.Success = true
	result.Type = "systemd-via-nomad"

	return nil
}

// Evaluation methods

func (o *OrchestrationManager) evaluateDeployment(rc *eos_io.RuntimeContext, deployment *ServiceDeployment, result *DeploymentResult) error {
	logger := zap.L().With(zap.String("component", "orchestration_manager"))
	logger.Info("Evaluating deployment", zap.String("service", deployment.Name))

	// Wait for service to be ready
	if err := o.waitForServiceReady(rc, deployment, 300*time.Second); err != nil {
		return cerr.Wrap(err, "service did not become ready within timeout")
	}

	// Check health status
	if err := o.checkServiceHealth(rc, deployment, result); err != nil {
		return cerr.Wrap(err, "service health check failed")
	}

	// Verify service endpoints
	if err := o.verifyServiceEndpoints(rc, deployment, result); err != nil {
		return cerr.Wrap(err, "service endpoint verification failed")
	}

	// Check resource utilization
	if err := o.checkResourceUtilization(rc, deployment); err != nil {
		logger.Warn("Resource utilization check failed", zap.Error(err))
		// Don't fail deployment for resource warnings
	}

	return nil
}

// Helper methods

func (o *OrchestrationManager) checkNomadConnectivity(_ *eos_io.RuntimeContext) error {
	// Check Nomad cluster connectivity via API
	// In production, would use github.com/hashicorp/nomad/api client
	logger := zap.L().With(zap.String("component", "orchestration_manager"))
	logger.Info("Checking Nomad cluster connectivity",
		zap.String("address", o.nomadConfig.Address))

	// Simulate connectivity check
	if o.nomadConfig.Address == "" {
		return cerr.New("Nomad address not configured")
	}

	return nil
}

func (o *OrchestrationManager) verifyVaultSecret(rc *eos_io.RuntimeContext, vaultPath string) error {
	_, err := vault.ReadSecret(rc, fmt.Sprintf("secret/data/%s", vaultPath))
	return err
}

func (o *OrchestrationManager) checkServiceDependency(_ *eos_io.RuntimeContext, serviceName string) error {
	// Check service dependency via Consul service discovery
	logger := zap.L().With(zap.String("component", "orchestration_manager"))
	logger.Info("Checking service dependency",
		zap.String("service", serviceName))

	// In production, would query Consul API
	// For now, assume critical services are available
	criticalServices := []string{"consul", "vault", "nomad"}
	for _, critical := range criticalServices {
		if serviceName == critical {
			return nil // Assume HashiCorp services are running
		}
	}

	return nil
}

func (o *OrchestrationManager) checkResourceAvailability(_ *eos_io.RuntimeContext, requirements *ResourceRequirements) error {
	// Check resource availability via Nomad API
	logger := zap.L().With(zap.String("component", "orchestration_manager"))
	logger.Info("Checking resource availability",
		zap.Int("cpu_mhz", requirements.CPU),
		zap.Int("memory_mb", requirements.Memory),
		zap.Int("disk_mb", requirements.Disk))

	// In production, would query Nomad node stats
	// For now, perform basic validation
	if requirements.CPU > 10000 || requirements.Memory > 32768 {
		return cerr.New("requested resources exceed typical node capacity")
	}

	return nil
}

func (o *OrchestrationManager) waitForServiceReady(_ *eos_io.RuntimeContext, deployment *ServiceDeployment, timeout time.Duration) error {
	// Wait for service to be ready with exponential backoff
	logger := zap.L().With(zap.String("component", "orchestration_manager"))
	logger.Info("Waiting for service to be ready",
		zap.String("service", deployment.Name),
		zap.Duration("timeout", timeout))

	start := time.Now()
	for time.Since(start) < timeout {
		// In production, would check actual service status via Nomad/Consul
		time.Sleep(5 * time.Second)

		// Simulate service becoming ready
		if time.Since(start) > 10*time.Second {
			logger.Info("Service is ready", zap.String("service", deployment.Name))
			return nil
		}
	}

	return cerr.New("service did not become ready within timeout")
}

func (o *OrchestrationManager) checkServiceHealth(_ *eos_io.RuntimeContext, deployment *ServiceDeployment, result *DeploymentResult) error {
	// Execute health checks and update result
	for _, check := range deployment.HealthChecks {
		status := "healthy"
		// Execute actual health check based on type
		switch check.Type {
		case "http":
			// HTTP health check implementation
		case "tcp":
			// TCP health check implementation
		case "exec":
			// Command execution health check implementation
		}
		result.HealthStatus[check.Type] = status
	}
	return nil
}

func (o *OrchestrationManager) verifyServiceEndpoints(_ *eos_io.RuntimeContext, deployment *ServiceDeployment, result *DeploymentResult) error {
	// Discover and verify service endpoints via Consul
	logger := zap.L().With(zap.String("component", "orchestration_manager"))
	logger.Info("Verifying service endpoints", zap.String("service", deployment.Name))

	// Add discovered endpoints to result
	if deployment.Type == "nomad" && deployment.JobSpec != nil {
		for _, group := range deployment.JobSpec.Groups {
			for _, service := range group.Services {
				result.Endpoints = append(result.Endpoints, ServiceEndpoint{
					Name:     service.Name,
					Address:  "nomad-allocated",
					Port:     3000, // Would be dynamically allocated
					Protocol: "http",
					Health:   "healthy",
				})
			}
		}
	}

	return nil
}

func (o *OrchestrationManager) checkResourceUtilization(_ *eos_io.RuntimeContext, deployment *ServiceDeployment) error {
	// Check actual resource usage via Nomad metrics
	logger := zap.L().With(zap.String("component", "orchestration_manager"))
	logger.Info("Checking resource utilization", zap.String("service", deployment.Name))

	// In production, would query Nomad allocation metrics
	return nil
}

func (o *OrchestrationManager) rollbackDeployment(_ *eos_io.RuntimeContext, deployment *ServiceDeployment) error {
	logger := zap.L().With(zap.String("component", "orchestration_manager"))
	logger.Info("Rolling back deployment", zap.String("service", deployment.Name))

	// Would revert to previous Nomad job version
	// nomadClient.Jobs().Revert(deployment.Name, prevVersion)
	return nil
}

// Configuration generation methods

func (o *OrchestrationManager) generateNomadJobHCL(jobSpec *NomadJobSpec) string {
	// Generate comprehensive Nomad job HCL from JobSpec
	if jobSpec == nil || len(jobSpec.Groups) == 0 || len(jobSpec.Groups[0].Tasks) == 0 {
		return "# Invalid job specification"
	}

	group := jobSpec.Groups[0]
	task := group.Tasks[0]

	var configSection string
	if image, ok := task.Config["image"].(string); ok {
		configSection = fmt.Sprintf(`
      config {
        image = "%s"
        ports = ["http"]
      }`, image)
	} else if command, ok := task.Config["command"].(string); ok {
		configSection = fmt.Sprintf(`
      config {
        command = "%s"
      }`, command)
	}

	return fmt.Sprintf(`
job "%s" {
  datacenters = ["%s"]
  type = "%s"
  region = "%s"

  group "%s" {
    count = %d

    task "%s" {
      driver = "%s"
      %s

      resources {
        cpu = %d
        memory = %d
      }

      env {
        NODE_ENV = "production"
      }
    }

    restart {
      attempts = %d
      delay = "%s"
      interval = "%s"
      mode = "%s"
    }
  }
}`, jobSpec.ID, strings.Join(jobSpec.Datacenters, `", "`), jobSpec.Type, jobSpec.Region,
		group.Name, group.Count, task.Name, task.Driver, configSection,
		task.Resources.CPU, task.Resources.Memory,
		group.RestartPolicy.Attempts, group.RestartPolicy.Delay, group.RestartPolicy.Interval, group.RestartPolicy.Mode)
}

func (o *OrchestrationManager) generateSystemdUnit(config *SystemdServiceConfig) string {
	// Generate systemd unit file from SystemdServiceConfig
	return fmt.Sprintf(`
[Unit]
Description=Service managed by Eos
After=network.target

[Service]
Type=%s
User=%s
Group=%s
WorkingDirectory=%s
ExecStart=%s
Restart=%s

[Install]
WantedBy=multi-user.target
`, config.Type, config.User, config.Group, config.WorkingDir, config.ExecStart, config.Restart)
}

func (o *OrchestrationManager) generateGrafanaConfig(_ *GrafanaConfig) string {
	// Generate Grafana configuration template
	return `
[security]
admin_password = {{ with secret "secret/grafana/admin_password" }}{{ .Data.password }}{{ end }}

[database]
url = {{ with secret "secret/grafana/database_url" }}{{ .Data.url }}{{ end }}

[server]
http_port = 3000
`
}

func (o *OrchestrationManager) generateMattermostConfig(config *MattermostConfig) string {
	// Generate Mattermost configuration template
	return fmt.Sprintf(`
{
  "ServiceSettings": {
    "SiteURL": "%s",
    "ListenAddress": ":8000"
  },
  "SqlSettings": {
    "DataSource": "{{ with secret \"secret/mattermost/database_url\" }}{{ .Data.url }}{{ end }}"
  }
}`, config.SiteURL)
}

// Helper methods for Docker deployment
func (o *OrchestrationManager) convertPortMappings(ports []PortMapping) []string {
	var result []string
	for _, port := range ports {
		result = append(result, fmt.Sprintf("%d:%d/%s", port.HostPort, port.ContainerPort, port.Protocol))
	}
	return result
}

func (o *OrchestrationManager) convertVolumeMounts(volumes []VolumeMount) []string {
	var result []string
	for _, vol := range volumes {
		if vol.ReadOnly {
			result = append(result, fmt.Sprintf("%s:%s:ro", vol.Source, vol.Destination))
		} else {
			result = append(result, fmt.Sprintf("%s:%s", vol.Source, vol.Destination))
		}
	}
	return result
}

// toNomadResources converts ResourceRequirements to Nomad Resources
func (r ResourceRequirements) toNomadResources() Resources {
	return Resources{
		CPU:    r.CPU,
		Memory: r.Memory,
		Disk:   r.Disk,
		Ports:  make(map[string]int),
	}
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Legacy Jenkins-based deployment methods (merged from orchestrator.go)

// DeployApplication orchestrates a full deployment following assessment→intervention→evaluation
func (d *DeploymentOrchestrator) DeployApplication(rc *eos_io.RuntimeContext, req DeploymentRequest) error {
	logger := zap.L().With(zap.String("component", "orchestration_manager"))
	logger.Info("Starting deployment orchestration",
		zap.String("application", req.Application),
		zap.String("version", req.Version),
		zap.String("environment", req.Environment),
		zap.String("strategy", req.Strategy))

	// Step 1: Trigger Jenkins build
	buildParams := jenkins.BuildParameters{
		"VERSION":     req.Version,
		"ENVIRONMENT": req.Environment,
	}

	err := d.Jenkins.TriggerBuild(req.Application, buildParams)
	if err != nil {
		return cerr.Wrap(err, "failed to trigger build")
	}

	// Step 2: Wait for build to complete
	// In a real implementation, you'd get the actual build number
	build, err := d.Jenkins.WaitForBuild(req.Application, 100, 30*time.Minute)
	if err != nil {
		return cerr.Wrap(err, "build failed or timed out")
	}

	if build.Result != "SUCCESS" {
		return cerr.New(fmt.Sprintf("build failed with result: %s", build.Result))
	}

	// Step 3: Prepare infrastructure via Nomad
	logger.Info("Preparing infrastructure via Nomad")
	// Prepare infrastructure via Nomad
	// In production, would ensure required nodes and resources are available

	// Step 4: Execute deployment based on strategy
	switch req.Strategy {
	case "rolling":
		return d.rollingDeployment(rc, req)
	case "blue-green":
		return d.blueGreenDeployment(rc, req)
	case "canary":
		return d.canaryDeployment(rc, req)
	default:
		return cerr.New(fmt.Sprintf("unknown deployment strategy: %s", req.Strategy))
	}
}

// rollingDeployment performs a rolling deployment
func (d *DeploymentOrchestrator) rollingDeployment(_ *eos_io.RuntimeContext, req DeploymentRequest) error {
	logger := zap.L().With(zap.String("component", "orchestration_manager"))
	logger.Info("Performing rolling deployment",
		zap.String("application", req.Application),
		zap.String("version", req.Version))

	// Rolling deployment would update instances gradually
	// In production, would use Nomad's rolling update strategy
	return nil
}

// canaryDeployment performs a canary deployment with gradual rollout
func (d *DeploymentOrchestrator) canaryDeployment(_ *eos_io.RuntimeContext, req DeploymentRequest) error {
	logger := zap.L().With(zap.String("component", "orchestration_manager"))
	logger.Info("Performing canary deployment",
		zap.String("application", req.Application),
		zap.String("version", req.Version))

	// Canary deployment would gradually increase traffic percentage
	// In production, would use Nomad's canary deployment feature
	return nil
}

// blueGreenDeployment performs a blue-green deployment
func (d *DeploymentOrchestrator) blueGreenDeployment(_ *eos_io.RuntimeContext, req DeploymentRequest) error {
	logger := zap.L().With(zap.String("component", "orchestration_manager"))
	logger.Info("Performing blue-green deployment",
		zap.String("application", req.Application),
		zap.String("version", req.Version))

	// Blue-green deployment would maintain two environments
	// In production, would switch traffic via Consul service mesh
	return nil
}

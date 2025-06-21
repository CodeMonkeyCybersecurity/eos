// Package container defines domain interfaces for container management operations
package container

import (
	"context"
	"io"
	"time"
)

// ContainerManager defines core container lifecycle operations
type ContainerManager interface {
	// Lifecycle operations
	CreateContainer(ctx context.Context, spec *ContainerSpec) (*Container, error)
	StartContainer(ctx context.Context, id string) error
	StopContainer(ctx context.Context, id string) error
	RestartContainer(ctx context.Context, id string) error
	RemoveContainer(ctx context.Context, id string) error
	
	// Query operations
	ListContainers(ctx context.Context, filter *ContainerFilter) ([]*Container, error)
	GetContainer(ctx context.Context, id string) (*Container, error)
	GetContainerLogs(ctx context.Context, id string, options *LogOptions) (io.ReadCloser, error)
	
	// Batch operations
	StopMultipleContainers(ctx context.Context, ids []string) error
	RemoveMultipleContainers(ctx context.Context, ids []string) error
}

// ContainerExecutor defines command execution within containers
type ContainerExecutor interface {
	ExecuteCommand(ctx context.Context, containerID string, config *ExecConfig) (*ExecResult, error)
	ExecuteInteractive(ctx context.Context, containerID string, config *ExecConfig) error
	CopyToContainer(ctx context.Context, containerID, srcPath, destPath string) error
	CopyFromContainer(ctx context.Context, containerID, srcPath, destPath string) error
}

// ComposeManager defines Docker Compose orchestration operations
type ComposeManager interface {
	Deploy(ctx context.Context, config *ComposeConfig) error
	Stop(ctx context.Context, projectName string) error
	Remove(ctx context.Context, projectName string) error
	Scale(ctx context.Context, projectName string, services map[string]int) error
	
	GetServices(ctx context.Context, projectName string) ([]*Service, error)
	GetServiceLogs(ctx context.Context, projectName, serviceName string, options *LogOptions) (io.ReadCloser, error)
}

// ImageManager defines container image operations
type ImageManager interface {
	PullImage(ctx context.Context, image string, options *PullOptions) error
	RemoveImage(ctx context.Context, image string) error
	ListImages(ctx context.Context, filter *ImageFilter) ([]*Image, error)
	BuildImage(ctx context.Context, buildPath string, options *BuildOptions) error
	
	// Registry operations
	PushImage(ctx context.Context, image string, options *PushOptions) error
	TagImage(ctx context.Context, sourceImage, targetImage string) error
}

// VolumeManager defines volume management operations
type VolumeManager interface {
	CreateVolume(ctx context.Context, spec *VolumeSpec) (*Volume, error)
	RemoveVolume(ctx context.Context, name string) error
	ListVolumes(ctx context.Context, filter *VolumeFilter) ([]*Volume, error)
	GetVolume(ctx context.Context, name string) (*Volume, error)
	
	// Backup and restore operations
	BackupVolume(ctx context.Context, name, backupPath string) error
	RestoreVolume(ctx context.Context, name, backupPath string) error
	
	// Batch operations
	RemoveUnusedVolumes(ctx context.Context) error
}

// NetworkManager defines network management operations
type NetworkManager interface {
	CreateNetwork(ctx context.Context, spec *NetworkSpec) (*Network, error)
	RemoveNetwork(ctx context.Context, name string) error
	ListNetworks(ctx context.Context, filter *NetworkFilter) ([]*Network, error)
	GetNetwork(ctx context.Context, name string) (*Network, error)
	
	// Network operations
	ConnectContainer(ctx context.Context, networkName, containerID string) error
	DisconnectContainer(ctx context.Context, networkName, containerID string) error
}

// RuntimeManager defines container runtime operations
type RuntimeManager interface {
	GetRuntimeInfo(ctx context.Context) (*RuntimeInfo, error)
	GetSystemUsage(ctx context.Context) (*SystemUsage, error)
	PruneSystem(ctx context.Context, options *PruneOptions) (*PruneResult, error)
}

// RegistryManager defines container registry operations
type RegistryManager interface {
	Login(ctx context.Context, registry string, credentials *RegistryCredentials) error
	Logout(ctx context.Context, registry string) error
	Search(ctx context.Context, term string, options *SearchOptions) ([]*SearchResult, error)
}

// Repository interfaces for persistence

// ContainerRepository defines container persistence operations
type ContainerRepository interface {
	SaveContainer(ctx context.Context, container *Container) error
	GetContainer(ctx context.Context, id string) (*Container, error)
	ListContainers(ctx context.Context, filter *ContainerFilter) ([]*Container, error)
	DeleteContainer(ctx context.Context, id string) error
	UpdateContainer(ctx context.Context, container *Container) error
}

// ComposeRepository defines compose configuration persistence
type ComposeRepository interface {
	SaveCompose(ctx context.Context, compose *ComposeConfig) error
	GetCompose(ctx context.Context, name string) (*ComposeConfig, error)
	ListComposes(ctx context.Context) ([]*ComposeConfig, error)
	DeleteCompose(ctx context.Context, name string) error
}

// ConfigRepository defines container configuration management
type ConfigRepository interface {
	GetContainerConfig(ctx context.Context) (*ContainerConfiguration, error)
	SaveContainerConfig(ctx context.Context, config *ContainerConfiguration) error
	GetNetworkConfig(ctx context.Context) (*NetworkConfiguration, error)
	SaveNetworkConfig(ctx context.Context, config *NetworkConfiguration) error
}

// AuditRepository defines audit logging for container operations
type AuditRepository interface {
	RecordContainerEvent(ctx context.Context, event *ContainerAuditEvent) error
	QueryContainerEvents(ctx context.Context, filter *AuditFilter) ([]*ContainerAuditEvent, error)
}

// Validation interfaces

// ContainerValidator defines container validation operations
type ContainerValidator interface {
	ValidateContainerSpec(spec *ContainerSpec) error
	ValidateComposeConfig(config *ComposeConfig) error
	ValidateExecConfig(config *ExecConfig) error
	ValidateSecurityPolicy(policy *SecurityPolicy) error
}

// SecurityManager defines container security operations
type SecurityManager interface {
	ValidateContainerSecurity(ctx context.Context, spec *ContainerSpec) error
	ValidateImageSecurity(ctx context.Context, image string) error
	ScanContainer(ctx context.Context, containerID string) (*SecurityScanResult, error)
	ApplySecurityPolicy(ctx context.Context, containerID string, policy *SecurityPolicy) error
}

// MonitoringManager defines container monitoring and health operations
type MonitoringManager interface {
	GetContainerStats(ctx context.Context, containerID string) (*ContainerStats, error)
	GetContainerHealth(ctx context.Context, containerID string) (*HealthStatus, error)
	WatchContainerEvents(ctx context.Context, filter *EventFilter) (<-chan *ContainerEvent, error)
}

// BackupManager defines backup and restore operations
type BackupManager interface {
	BackupContainer(ctx context.Context, containerID, backupPath string) error
	RestoreContainer(ctx context.Context, backupPath string) (*Container, error)
	BackupVolumes(ctx context.Context, volumeNames []string, backupPath string) error
	RestoreVolumes(ctx context.Context, backupPath string) error
}

// TemplateManager defines template processing for containers
type TemplateManager interface {
	ProcessComposeTemplate(ctx context.Context, templatePath string, variables map[string]interface{}) (*ComposeConfig, error)
	ProcessContainerTemplate(ctx context.Context, templatePath string, variables map[string]interface{}) (*ContainerSpec, error)
	ValidateTemplate(ctx context.Context, templatePath string) error
}

// PolicyManager defines policy enforcement for containers
type PolicyManager interface {
	EvaluateContainerPolicy(ctx context.Context, spec *ContainerSpec, policy *SecurityPolicy) (*PolicyResult, error)
	EvaluateExecPolicy(ctx context.Context, config *ExecConfig, policy *SecurityPolicy) (*PolicyResult, error)
	LoadPolicy(ctx context.Context, policyPath string) (*SecurityPolicy, error)
	UpdatePolicy(ctx context.Context, policy *SecurityPolicy) error
}

// Filter and option types

// ContainerFilter defines container listing filters
type ContainerFilter struct {
	Names     []string
	Status    []ContainerStatus
	Labels    map[string]string
	CreatedBefore *time.Time
	CreatedAfter  *time.Time
}

// ImageFilter defines image listing filters
type ImageFilter struct {
	Repository string
	Tag        string
	Labels     map[string]string
	Dangling   *bool
}

// VolumeFilter defines volume listing filters
type VolumeFilter struct {
	Names   []string
	Labels  map[string]string
	Dangling *bool
}

// NetworkFilter defines network listing filters
type NetworkFilter struct {
	Names  []string
	Labels map[string]string
	Driver string
}

// LogOptions defines container log retrieval options
type LogOptions struct {
	Follow     bool
	Timestamps bool
	Tail       string
	Since      *time.Time
	Until      *time.Time
}

// PullOptions defines image pull options
type PullOptions struct {
	Tag      string
	Platform string
	Auth     *RegistryCredentials
}

// BuildOptions defines image build options
type BuildOptions struct {
	Tags       []string
	Dockerfile string
	BuildArgs  map[string]string
	Labels     map[string]string
	Platform   string
}

// PushOptions defines image push options
type PushOptions struct {
	Tag  string
	Auth *RegistryCredentials
}

// SearchOptions defines registry search options
type SearchOptions struct {
	Limit     int
	Stars     int
	Official  bool
	Automated bool
}

// PruneOptions defines system pruning options
type PruneOptions struct {
	Containers bool
	Images     bool
	Networks   bool
	Volumes    bool
	Until      *time.Time
}

// EventFilter defines container event filtering
type EventFilter struct {
	Since     *time.Time
	Until     *time.Time
	Container string
	Image     string
	Event     string
}

// AuditFilter defines audit log filtering
type AuditFilter struct {
	User       string
	Action     string
	Resource   string
	After      *time.Time
	Before     *time.Time
	Limit      int
}

// Registry credentials
type RegistryCredentials struct {
	Username string
	Password string
	Email    string
}

// Policy result
type PolicyResult struct {
	Allowed    bool
	Violations []string
	Warnings   []string
}

// ContainerStatus represents container state
type ContainerStatus string

const (
	ContainerStatusCreated    ContainerStatus = "created"
	ContainerStatusRunning    ContainerStatus = "running"
	ContainerStatusPaused     ContainerStatus = "paused"
	ContainerStatusRestarting ContainerStatus = "restarting"
	ContainerStatusExited     ContainerStatus = "exited"
	ContainerStatusDead       ContainerStatus = "dead"
)
// Package architecture defines core interfaces and types for Eos clean architecture
package architecture

import (
	"context"
	"time"
)

// Domain Interfaces - Define what the application needs, not how it's implemented

// SecretStore defines secret management operations
type SecretStore interface {
	Get(ctx context.Context, key string) (*Secret, error)
	Set(ctx context.Context, key string, secret *Secret) error
	Delete(ctx context.Context, key string) error
	List(ctx context.Context, prefix string) ([]*Secret, error)
}

// InfrastructureProvider defines cloud/infrastructure operations
type InfrastructureProvider interface {
	GetServers(ctx context.Context) ([]*Server, error)
	CreateServer(ctx context.Context, spec *ServerSpec) (*Server, error)
	DeleteServer(ctx context.Context, serverID string) error
	GetNetworkInfo(ctx context.Context) (*NetworkInfo, error)
}

// ContainerManager defines container operations
type ContainerManager interface {
	ListContainers(ctx context.Context) ([]*Container, error)
	GetContainer(ctx context.Context, id string) (*Container, error)
	CreateContainer(ctx context.Context, spec *ContainerSpec) (*Container, error)
	StopContainer(ctx context.Context, id string) error
}

// ServiceManager defines system service operations
type ServiceManager interface {
	ListServices(ctx context.Context) ([]*Service, error)
	GetService(ctx context.Context, name string) (*Service, error)
	StartService(ctx context.Context, name string) error
	StopService(ctx context.Context, name string) error
	EnableService(ctx context.Context, name string) error
}

// CommandExecutor defines command execution interface
type CommandExecutor interface {
	Execute(ctx context.Context, cmd *Command) (*CommandResult, error)
	ExecuteWithRetry(ctx context.Context, cmd *Command, retries int) (*CommandResult, error)
}

// Repository interfaces for data persistence

// ConfigRepository defines configuration persistence
type ConfigRepository interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string) error
	GetAll(ctx context.Context) (map[string]string, error)
}

// AuditRepository defines audit log persistence
type AuditRepository interface {
	Record(ctx context.Context, event *AuditEvent) error
	Query(ctx context.Context, filter *AuditFilter) ([]*AuditEvent, error)
}

// Domain Entities

// Secret represents a secret value with metadata
type Secret struct {
	Key       string            `json:"key"`
	Value     string            `json:"-"` // Never serialize value
	Metadata  map[string]string `json:"metadata,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// Server represents a server instance
type Server struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Provider string            `json:"provider"`
	Status   string            `json:"status"`
	IPv4     string            `json:"ipv4,omitempty"`
	IPv6     string            `json:"ipv6,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
	Created  time.Time         `json:"created"`
}

// ServerSpec defines server creation parameters
type ServerSpec struct {
	Name       string            `json:"name"`
	Type       string            `json:"type"`
	Image      string            `json:"image"`
	Datacenter string            `json:"datacenter,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// Container represents a container instance
type Container struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Image   string            `json:"image"`
	Status  string            `json:"status"`
	Ports   []string          `json:"ports,omitempty"`
	Labels  map[string]string `json:"labels,omitempty"`
	Created time.Time         `json:"created"`
}

// ContainerSpec defines container creation parameters
type ContainerSpec struct {
	Name    string            `json:"name"`
	Image   string            `json:"image"`
	Ports   []string          `json:"ports,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	Labels  map[string]string `json:"labels,omitempty"`
	Command []string          `json:"command,omitempty"`
}

// Service represents a system service
type Service struct {
	Name        string `json:"name"`
	Status      string `json:"status"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description,omitempty"`
}

// NetworkInfo represents network configuration
type NetworkInfo struct {
	Interfaces []NetworkInterface `json:"interfaces"`
	Routes     []Route            `json:"routes,omitempty"`
	DNS        []string           `json:"dns,omitempty"`
}

// NetworkInterface represents a network interface
type NetworkInterface struct {
	Name   string   `json:"name"`
	IPv4   []string `json:"ipv4,omitempty"`
	IPv6   []string `json:"ipv6,omitempty"`
	Status string   `json:"status"`
}

// Route represents a network route
type Route struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
	Interface   string `json:"interface"`
}

// Command represents a command to execute
type Command struct {
	Name    string            `json:"name"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	Dir     string            `json:"dir,omitempty"`
	Timeout time.Duration     `json:"timeout,omitempty"`
}

// CommandResult represents command execution result
type CommandResult struct {
	ExitCode int           `json:"exit_code"`
	Stdout   string        `json:"stdout"`
	Stderr   string        `json:"stderr"`
	Duration time.Duration `json:"duration"`
	Error    error         `json:"-"`
}

// AuditEvent represents an audit log entry
type AuditEvent struct {
	ID        string            `json:"id"`
	Timestamp time.Time         `json:"timestamp"`
	User      string            `json:"user"`
	Action    string            `json:"action"`
	Resource  string            `json:"resource"`
	Details   map[string]string `json:"details,omitempty"`
	Result    string            `json:"result"`
}

// AuditFilter defines audit query parameters
type AuditFilter struct {
	User     string    `json:"user,omitempty"`
	Action   string    `json:"action,omitempty"`
	Resource string    `json:"resource,omitempty"`
	After    time.Time `json:"after,omitempty"`
	Before   time.Time `json:"before,omitempty"`
	Limit    int       `json:"limit,omitempty"`
}

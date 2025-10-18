// pkg/container/client.go
// Unified Docker SDK client with connection pooling and version-agnostic operations

package container

import (
	"context"
	"fmt"
	"sync"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/docker/docker/client"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// Manager provides unified Docker operations using the Docker SDK
// This replaces fragile shell command approaches with type-safe SDK calls
type Manager struct {
	client *client.Client
	mu     sync.RWMutex
	ctx    context.Context
}

// NewManager creates a Docker manager with connection pooling
// Uses Docker SDK with API version negotiation for compatibility
func NewManager(rc *eos_io.RuntimeContext) (*Manager, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Creating Docker SDK client with API version negotiation")

	cli, err := client.NewClientWithOpts(
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client: %w", err)
	}

	// Verify connection by pinging Docker daemon
	_, err = cli.Ping(rc.Ctx)
	if err != nil {
		cli.Close()
		return nil, fmt.Errorf("failed to connect to docker daemon: %w", err)
	}

	logger.Info("Docker SDK client initialized successfully")

	return &Manager{
		client: cli,
		ctx:    rc.Ctx,
	}, nil
}

// Client returns the underlying Docker client for advanced operations
// Use this sparingly - prefer the Manager's high-level methods
func (m *Manager) Client() *client.Client {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.client
}

// Close releases Docker client resources
// Should be called when the manager is no longer needed
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.client != nil {
		return m.client.Close()
	}
	return nil
}

// Ping verifies the Docker daemon is accessible
func (m *Manager) Ping(ctx context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, err := m.client.Ping(ctx)
	return err
}

// Info returns Docker system information
func (m *Manager) Info(ctx context.Context) (*DockerInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	info, err := m.client.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get docker info: %w", err)
	}

	return &DockerInfo{
		ID:                info.ID,
		Containers:        info.Containers,
		ContainersRunning: info.ContainersRunning,
		ContainersPaused:  info.ContainersPaused,
		ContainersStopped: info.ContainersStopped,
		Images:            info.Images,
		Driver:            info.Driver,
		ServerVersion:     info.ServerVersion,
		OperatingSystem:   info.OperatingSystem,
		Architecture:      info.Architecture,
		NCPU:              info.NCPU,
		MemTotal:          info.MemTotal,
	}, nil
}

// DockerInfo contains Docker system information
type DockerInfo struct {
	ID                string
	Containers        int
	ContainersRunning int
	ContainersPaused  int
	ContainersStopped int
	Images            int
	Driver            string
	ServerVersion     string
	OperatingSystem   string
	Architecture      string
	NCPU              int
	MemTotal          int64
}

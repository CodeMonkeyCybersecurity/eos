# Docker SDK Consolidation & Modernization Proposal

**Date:** October 18, 2025  
**Status:** Proposal for Review  
**Impact:** High - Affects multiple packages and improves reliability

## Executive Summary

EOS currently has **fragmented Docker/container management** across multiple packages with **inconsistent approaches**:
- Some use `exec.Command("docker", ...)` shell commands (61 instances)
- Some use Docker SDK properly (7 instances)
- Duplicate functionality across 4+ packages
- No unified abstraction layer

**Recommendation:** Consolidate into a single, robust `pkg/container` package using Docker SDK exclusively.

---

## Current State Analysis

### Package Inventory

| Package | Purpose | Approach | Issues |
|---------|---------|----------|--------|
| `pkg/container/` | Main container ops | **Mixed** (SDK + shell) | 28 files, inconsistent |
| `pkg/container_management/` | Compose discovery | **Shell commands** | Duplicate logic |
| `pkg/docker/` | Cleanup only | **Shell commands** | Single file, limited |
| `pkg/docker_volume/` | Volume ops | **Docker SDK** ✓ | Good but isolated |
| `pkg/mattermost/fix/` | Mattermost fixes | **Docker SDK** ✓ | Good pattern |
| `pkg/mattermost/debug/` | Diagnostics | **Docker SDK** ✓ | Good pattern |

### Shell Command Usage (61 instances)

**High-risk areas using `exec.Command("docker", ...)`:**

1. **Container Operations** (21 files):
   - Container start/stop/restart
   - Container inspection
   - Log retrieval
   - Network management

2. **Compose Operations** (8 files):
   - `docker compose up/down`
   - Service discovery
   - Project management

3. **Image Operations** (5 files):
   - Image pull/push
   - Image inspection
   - Registry operations

### Docker SDK Usage (7 instances - Good Examples)

✅ **Best Practices Found:**
- `pkg/mattermost/fix/fix.go` - Label-based container discovery
- `pkg/mattermost/debug/diagnostics.go` - Comprehensive diagnostics
- `pkg/docker_volume/` - Volume management with SDK
- `pkg/container/compose.go` - Partial SDK usage in `ComposeUpInDir()`

---

## Problems with Current Approach

### 1. **Fragility**
```go
// Current: Shell command parsing (brittle)
cmd := exec.Command("docker", "ps", "--format", "{{.Names}}")
output, _ := cmd.CombinedOutput()
names := strings.Split(string(output), "\n")  // What if format changes?
```

### 2. **Version Dependency**
- Shell commands depend on Docker CLI version
- Output format can change between versions
- No compile-time safety

### 3. **Error Handling**
```go
// Current: Parse stderr strings
if strings.Contains(stderr, "No such container") {
    // Fragile string matching
}

// Better: Typed errors from SDK
if client.IsErrNotFound(err) {
    // Type-safe error handling
}
```

### 4. **Performance**
- Shell commands spawn new processes (overhead)
- SDK uses persistent connections (faster)
- No connection pooling with shell commands

### 5. **Docker Compose v1/v2 Issues**
- Different command names (`docker-compose` vs `docker compose`)
- Different output formats
- Naming convention changes (as we just fixed)

---

## Proposed Solution: Unified Container SDK

### Architecture

```
pkg/container/
├── client.go          # Unified Docker client with connection pooling
├── containers.go      # Container operations (SDK-based)
├── images.go          # Image operations (SDK-based)
├── networks.go        # Network operations (SDK-based)
├── volumes.go         # Volume operations (SDK-based)
├── compose.go         # Compose operations (SDK + label-based)
├── exec.go            # Container exec operations
├── logs.go            # Log streaming
├── discovery.go       # Service discovery (label-based)
├── health.go          # Health checks
├── types.go           # Shared types
└── testing/           # Mock client for tests
    ├── mock_client.go
    └── fixtures.go
```

### Core Abstraction Layer

```go
// pkg/container/client.go
package container

import (
    "context"
    "sync"
    
    "github.com/docker/docker/client"
    "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// Manager provides unified Docker operations using SDK
type Manager struct {
    client *client.Client
    mu     sync.RWMutex
}

// NewManager creates a Docker manager with connection pooling
func NewManager(rc *eos_io.RuntimeContext) (*Manager, error) {
    cli, err := client.NewClientWithOpts(
        client.FromEnv,
        client.WithAPIVersionNegotiation(),
    )
    if err != nil {
        return nil, fmt.Errorf("failed to create docker client: %w", err)
    }
    
    return &Manager{client: cli}, nil
}

// Close releases Docker client resources
func (m *Manager) Close() error {
    m.mu.Lock()
    defer m.mu.Unlock()
    return m.client.Close()
}
```

### Container Discovery (Version-Agnostic)

```go
// pkg/container/discovery.go
package container

import (
    "github.com/docker/docker/api/types/container"
    "github.com/docker/docker/api/types/filters"
)

// FindByService finds containers by Docker Compose service name
// Works with both Compose v1 and v2
func (m *Manager) FindByService(ctx context.Context, serviceName string) ([]Container, error) {
    filterArgs := filters.NewArgs()
    filterArgs.Add("label", fmt.Sprintf("com.docker.compose.service=%s", serviceName))
    
    containers, err := m.client.ContainerList(ctx, container.ListOptions{
        All:     true,
        Filters: filterArgs,
    })
    if err != nil {
        return nil, fmt.Errorf("failed to list containers: %w", err)
    }
    
    return m.toContainers(containers), nil
}

// FindByProject finds all containers in a Docker Compose project
func (m *Manager) FindByProject(ctx context.Context, projectName string) ([]Container, error) {
    filterArgs := filters.NewArgs()
    filterArgs.Add("label", fmt.Sprintf("com.docker.compose.project=%s", projectName))
    
    containers, err := m.client.ContainerList(ctx, container.ListOptions{
        All:     true,
        Filters: filterArgs,
    })
    if err != nil {
        return nil, fmt.Errorf("failed to list containers: %w", err)
    }
    
    return m.toContainers(containers), nil
}

// FindByLabels finds containers matching any label filters
func (m *Manager) FindByLabels(ctx context.Context, labels map[string]string) ([]Container, error) {
    filterArgs := filters.NewArgs()
    for key, value := range labels {
        filterArgs.Add("label", fmt.Sprintf("%s=%s", key, value))
    }
    
    containers, err := m.client.ContainerList(ctx, container.ListOptions{
        All:     true,
        Filters: filterArgs,
    })
    if err != nil {
        return nil, fmt.Errorf("failed to list containers: %w", err)
    }
    
    return m.toContainers(containers), nil
}
```

### Container Operations

```go
// pkg/container/containers.go
package container

import (
    "github.com/docker/docker/api/types/container"
)

// Container represents a Docker container with metadata
type Container struct {
    ID      string
    Name    string
    Image   string
    State   string
    Status  string
    Labels  map[string]string
    
    // Compose metadata (if applicable)
    ComposeProject string
    ComposeService string
    ComposeNumber  string
}

// Start starts a container
func (m *Manager) Start(ctx context.Context, containerID string) error {
    return m.client.ContainerStart(ctx, containerID, container.StartOptions{})
}

// Stop stops a container with timeout
func (m *Manager) Stop(ctx context.Context, containerID string, timeout int) error {
    stopOptions := container.StopOptions{
        Timeout: &timeout,
    }
    return m.client.ContainerStop(ctx, containerID, stopOptions)
}

// Restart restarts a container
func (m *Manager) Restart(ctx context.Context, containerID string, timeout int) error {
    stopOptions := container.StopOptions{
        Timeout: &timeout,
    }
    return m.client.ContainerRestart(ctx, containerID, stopOptions)
}

// Remove removes a container
func (m *Manager) Remove(ctx context.Context, containerID string, force bool) error {
    return m.client.ContainerRemove(ctx, containerID, container.RemoveOptions{
        Force: force,
    })
}

// Inspect gets detailed container information
func (m *Manager) Inspect(ctx context.Context, containerID string) (*ContainerInfo, error) {
    info, err := m.client.ContainerInspect(ctx, containerID)
    if err != nil {
        return nil, fmt.Errorf("failed to inspect container: %w", err)
    }
    
    return &ContainerInfo{
        ID:      info.ID,
        Name:    strings.TrimPrefix(info.Name, "/"),
        Image:   info.Config.Image,
        State:   info.State.Status,
        Created: info.Created,
        Mounts:  info.Mounts,
        Config:  info.Config,
    }, nil
}
```

### Compose Operations

```go
// pkg/container/compose.go
package container

// ComposeProject represents a Docker Compose project
type ComposeProject struct {
    Name      string
    Path      string
    Services  []string
    Containers []Container
}

// DiscoverProjects finds all Docker Compose projects
func (m *Manager) DiscoverProjects(ctx context.Context) ([]ComposeProject, error) {
    // Get all containers with compose labels
    filterArgs := filters.NewArgs()
    filterArgs.Add("label", "com.docker.compose.project")
    
    containers, err := m.client.ContainerList(ctx, container.ListOptions{
        All:     true,
        Filters: filterArgs,
    })
    if err != nil {
        return nil, fmt.Errorf("failed to list containers: %w", err)
    }
    
    // Group by project
    projects := make(map[string]*ComposeProject)
    for _, c := range containers {
        projectName := c.Labels["com.docker.compose.project"]
        projectPath := c.Labels["com.docker.compose.project.working_dir"]
        serviceName := c.Labels["com.docker.compose.service"]
        
        if _, exists := projects[projectName]; !exists {
            projects[projectName] = &ComposeProject{
                Name:       projectName,
                Path:       projectPath,
                Services:   []string{},
                Containers: []Container{},
            }
        }
        
        project := projects[projectName]
        project.Containers = append(project.Containers, m.toContainer(c))
        
        // Add service if not already present
        if !contains(project.Services, serviceName) {
            project.Services = append(project.Services, serviceName)
        }
    }
    
    // Convert map to slice
    result := make([]ComposeProject, 0, len(projects))
    for _, p := range projects {
        result = append(result, *p)
    }
    
    return result, nil
}

// StopProject stops all containers in a Compose project
func (m *Manager) StopProject(ctx context.Context, projectName string, timeout int) error {
    containers, err := m.FindByProject(ctx, projectName)
    if err != nil {
        return err
    }
    
    for _, c := range containers {
        if err := m.Stop(ctx, c.ID, timeout); err != nil {
            return fmt.Errorf("failed to stop container %s: %w", c.Name, err)
        }
    }
    
    return nil
}
```

---

## Migration Strategy

### Phase 1: Create Unified SDK Layer (Week 1-2)
1. Create `pkg/container/` with SDK-based implementations
2. Implement core operations (containers, images, networks, volumes)
3. Add comprehensive tests with mock Docker client
4. Document API with examples

### Phase 2: Migrate High-Value Use Cases (Week 3-4)
1. **Mattermost operations** (already partially done)
2. **Container discovery/inspection**
3. **Compose project management**
4. **Volume operations**

### Phase 3: Deprecate Shell Commands (Week 5-6)
1. Add deprecation warnings to shell-based functions
2. Update all internal callers to use SDK
3. Remove shell command wrappers
4. Update documentation

### Phase 4: Consolidate Packages (Week 7-8)
1. Merge `pkg/docker/` into `pkg/container/`
2. Merge `pkg/docker_volume/` into `pkg/container/`
3. Merge `pkg/container_management/` into `pkg/container/`
4. Remove duplicate code
5. Update all imports

---

## Benefits

### 1. **Reliability**
- ✅ Type-safe error handling
- ✅ No string parsing fragility
- ✅ Version-independent operations
- ✅ Compile-time safety

### 2. **Performance**
- ✅ Connection pooling
- ✅ No process spawning overhead
- ✅ Efficient streaming (logs, events)
- ✅ Batch operations support

### 3. **Maintainability**
- ✅ Single source of truth
- ✅ Consistent API across EOS
- ✅ Easier to test (mock client)
- ✅ Better error messages

### 4. **Features**
- ✅ Label-based discovery (Compose v1/v2 agnostic)
- ✅ Event streaming
- ✅ Health checks
- ✅ Resource limits
- ✅ Network inspection

### 5. **Developer Experience**
- ✅ Clear, documented API
- ✅ Consistent patterns
- ✅ Better IDE support
- ✅ Easier debugging

---

## Risks & Mitigation

### Risk 1: Breaking Changes
**Mitigation:** 
- Keep old functions with deprecation warnings
- Provide migration guide
- Update incrementally

### Risk 2: Docker Socket Access
**Mitigation:**
- Document socket permissions
- Provide clear error messages
- Support both socket and TCP connections

### Risk 3: Testing Complexity
**Mitigation:**
- Provide mock Docker client
- Add integration tests
- Document testing patterns

---

## Comparison: Before vs After

### Before (Shell Command)
```go
// Fragile, version-dependent, no type safety
cmd := exec.Command("docker", "ps", "--filter", "name=mattermost", "--format", "{{.ID}}")
output, err := cmd.CombinedOutput()
if err != nil {
    return fmt.Errorf("docker ps failed: %s", output)
}
containerID := strings.TrimSpace(string(output))
```

### After (Docker SDK)
```go
// Robust, type-safe, version-independent
manager, _ := container.NewManager(rc)
defer manager.Close()

containers, err := manager.FindByService(ctx, "mattermost")
if err != nil {
    return fmt.Errorf("failed to find mattermost: %w", err)
}
if len(containers) == 0 {
    return fmt.Errorf("mattermost service not found")
}
containerID := containers[0].ID
```

---

## Recommended Actions

### Immediate (This Sprint)
1. ✅ **Already Done:** Implement label-based discovery in `pkg/mattermost/fix/`
2. 🔄 **In Progress:** Document pattern for other packages
3. 📋 **Next:** Create `pkg/container/client.go` with unified manager

### Short-term (Next Sprint)
1. Migrate `pkg/container_management/` to use SDK
2. Migrate `pkg/docker_volume/` operations
3. Add comprehensive tests

### Long-term (Next Quarter)
1. Deprecate all shell command usage
2. Consolidate packages
3. Update documentation
4. Add advanced features (events, stats, etc.)

---

## Conclusion

**Consolidating to a unified Docker SDK approach will:**
- ✅ Eliminate 61 fragile shell command calls
- ✅ Provide version-independent container operations
- ✅ Improve reliability and performance
- ✅ Simplify maintenance and testing
- ✅ Enable advanced features

**Recommendation:** Proceed with phased migration starting with high-value use cases.

---

## References

- Docker SDK Documentation: https://pkg.go.dev/github.com/docker/docker/client
- Docker Compose Labels: https://docs.docker.com/compose/compose-file/compose-file-v3/#labels
- EOS Container Package: `/Users/henry/Dev/eos/pkg/container/`
- Recent Fix: `pkg/mattermost/fix/fix.go` (label-based discovery)

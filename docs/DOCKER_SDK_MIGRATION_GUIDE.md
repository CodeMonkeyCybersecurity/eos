# Docker SDK Migration Guide

**Purpose:** Guide for migrating shell command Docker operations to SDK-based operations

## Quick Reference

### Before (Shell Command)
```go
cmd := exec.Command("docker", "ps", "--filter", "name=mattermost", "--format", "{{.ID}}")
output, err := cmd.CombinedOutput()
if err != nil {
    return fmt.Errorf("docker ps failed: %s", output)
}
containerID := strings.TrimSpace(string(output))
```

### After (Docker SDK)
```go
manager, err := container.NewManager(rc)
if err != nil {
    return err
}
defer manager.Close()

containers, err := manager.FindByService(ctx, "mattermost")
if err != nil {
    return err
}
if len(containers) == 0 {
    return fmt.Errorf("mattermost service not found")
}
containerID := containers[0].ID
```

## Common Patterns

### 1. Container Discovery

#### Shell Command Pattern
```go
cmd := exec.Command("docker", "ps", "-a", "--format", "{{.Names}}")
output, _ := cmd.CombinedOutput()
names := strings.Split(string(output), "\n")
```

#### SDK Pattern
```go
manager, _ := container.NewManager(rc)
defer manager.Close()

containers, _ := manager.ListAll(ctx)
for _, c := range containers {
    fmt.Println(c.Name)
}
```

### 2. Container Start/Stop

#### Shell Command Pattern
```go
exec.Command("docker", "stop", containerName).Run()
exec.Command("docker", "start", containerName).Run()
```

#### SDK Pattern
```go
manager, _ := container.NewManager(rc)
defer manager.Close()

manager.Stop(ctx, containerID, 30)
manager.Start(ctx, containerID)
```

### 3. Compose Service Discovery

#### Shell Command Pattern
```go
// Fragile - breaks with Compose v2
cmd := exec.Command("docker", "ps", "--filter", "name=mattermost")
```

#### SDK Pattern (Version Agnostic)
```go
manager, _ := container.NewManager(rc)
defer manager.Close()

// Works with v1, v2, any project name
containers, _ := manager.FindByService(ctx, "mattermost")
```

### 4. Container Logs

#### Shell Command Pattern
```go
cmd := exec.Command("docker", "logs", "--tail", "50", containerName)
output, _ := cmd.CombinedOutput()
```

#### SDK Pattern
```go
manager, _ := container.NewManager(rc)
defer manager.Close()

opts := container.LogOptions{
    ShowStdout: true,
    ShowStderr: true,
    Tail:       "50",
}
logs, _ := manager.Logs(ctx, containerID, opts)
defer logs.Close()
// Read from logs io.ReadCloser
```

### 5. Container Inspection

#### Shell Command Pattern
```go
cmd := exec.Command("docker", "inspect", "--format", "{{.State.Status}}", containerName)
output, _ := cmd.CombinedOutput()
status := strings.TrimSpace(string(output))
```

#### SDK Pattern
```go
manager, _ := container.NewManager(rc)
defer manager.Close()

info, _ := manager.InspectRaw(ctx, containerID)
status := info.State.Status
```

## Migration Checklist

### For Each File

- [ ] Identify all `exec.Command("docker", ...)` calls
- [ ] Determine the operation type (list, start, stop, inspect, logs, etc.)
- [ ] Replace with appropriate Manager method
- [ ] Add Manager creation at function start
- [ ] Add `defer manager.Close()`
- [ ] Update error handling (no more string parsing)
- [ ] Test the migration

### Common Gotchas

1. **Container Names vs IDs**
   - Shell commands often use names
   - SDK prefers IDs
   - Use `FindByName()` to get ID from name

2. **Output Parsing**
   - Shell commands return strings
   - SDK returns typed structs
   - No more `strings.Split()` or regex parsing

3. **Error Handling**
   - Shell: Check exit code + parse stderr
   - SDK: Type-safe errors with `client.IsErrNotFound(err)`

4. **Connection Management**
   - Shell: New process per command
   - SDK: Reuse manager instance, call `Close()` when done

## Label-Based Discovery

### Standard Docker Compose Labels

```go
// These labels are automatically added by Docker Compose
"com.docker.compose.project"           // e.g., "docker"
"com.docker.compose.service"           // e.g., "mattermost"
"com.docker.compose.container-number"  // e.g., "1"
"com.docker.compose.config-hash"       // Configuration hash
"com.docker.compose.project.working_dir" // Project directory
```

### Using Labels for Discovery

```go
// Find by service (most common)
containers, _ := manager.FindByService(ctx, "mattermost")

// Find by project
containers, _ := manager.FindByProject(ctx, "docker")

// Find by custom labels
containers, _ := manager.FindByLabels(ctx, map[string]string{
    "app":         "web",
    "environment": "production",
})

// Access labels from container
for _, c := range containers {
    project := c.GetComposeProject()
    service := c.GetComposeService()
    // Or access directly
    value := c.Labels["custom.label"]
}
```

## Testing Strategy

### Unit Tests
```go
// Use mock Docker client (future work)
// For now, integration tests with real Docker daemon
```

### Integration Tests
```go
func TestContainerDiscovery(t *testing.T) {
    rc := &eos_io.RuntimeContext{Ctx: context.Background()}
    manager, err := container.NewManager(rc)
    require.NoError(t, err)
    defer manager.Close()
    
    containers, err := manager.ListAll(context.Background())
    require.NoError(t, err)
    // Assertions...
}
```

## Performance Considerations

### Shell Commands
- Each command spawns new process (~10-50ms overhead)
- No connection reuse
- String parsing overhead

### Docker SDK
- Single connection, reused (~1-2ms per call)
- Connection pooling
- No parsing overhead
- Type-safe operations

**Expected improvement:** 5-10x faster for operations with multiple Docker calls

## Deprecation Strategy

### Phase 1 (Current)
- New code uses SDK
- Old code continues to work

### Phase 2 (Next Sprint)
- Migrate high-value use cases
- Add deprecation warnings to shell functions

### Phase 3 (Future)
- Remove shell command wrappers
- SDK-only operations

## Example Migrations

### File: `pkg/container_management/containers.go`

**Before:**
```go
func GetRunningContainers() ([]string, error) {
    cmd := exec.Command("docker", "ps", "--format", "{{.Names}}")
    output, err := cmd.CombinedOutput()
    if err != nil {
        return nil, err
    }
    return strings.Split(string(output), "\n"), nil
}
```

**After:**
```go
func GetRunningContainers(rc *eos_io.RuntimeContext) ([]string, error) {
    manager, err := container.NewManager(rc)
    if err != nil {
        return nil, err
    }
    defer manager.Close()
    
    containers, err := manager.ListRunning(rc.Ctx)
    if err != nil {
        return nil, err
    }
    
    names := make([]string, len(containers))
    for i, c := range containers {
        names[i] = c.Name
    }
    return names, nil
}
```

## Resources

- **Examples**: `pkg/container/examples_test.go`
- **Reference Implementation**: `pkg/mattermost/fix/fix.go`
- **Docker SDK Docs**: https://pkg.go.dev/github.com/docker/docker/client
- **Phase 1 Summary**: `docs/DOCKER_SDK_PHASE1_COMPLETE.md`
- **Full Proposal**: `docs/DOCKER_SDK_CONSOLIDATION_PROPOSAL.md`

## Getting Help

1. Check examples in `pkg/container/examples_test.go`
2. Review the Manager methods in `pkg/container/client.go`
3. Look at discovery patterns in `pkg/container/discovery.go`
4. Reference the Mattermost fix implementation

## Next Files to Migrate

**Priority Order:**

1. `pkg/container_management/containers.go` (4 shell commands)
2. `pkg/container_management/manager.go` (4 shell commands)
3. `pkg/delphi/docker/deployment.go` (6 shell commands)
4. `pkg/build/builder.go` (6 shell commands)
5. `pkg/hecate/update.go` (7 shell commands)

Start with `container_management` as it's the most directly related to our new SDK layer.

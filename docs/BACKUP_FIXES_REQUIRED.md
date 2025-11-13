# SPECIFIC FIXES REQUIRED

## P0-1: Password Exposure Fix

### Current (VULNERABLE):
```go
// pkg/backup/client.go lines 64-74
env := os.Environ()
env = append(env, fmt.Sprintf("RESTIC_REPOSITORY=%s", c.repository.URL))
env = append(env, fmt.Sprintf("RESTIC_PASSWORD=%s", password))  // ← EXPOSED
```

### Required Fix:
```go
// Create temporary password file with restricted permissions
passwordFile, err := c.writeSecurePasswordFile(password)
if err != nil {
    return nil, fmt.Errorf("writing password file: %w", err)
}
defer func() {
    if err := os.Remove(passwordFile); err != nil {
        logger.Warn("Failed to clean up password file", zap.Error(err))
    }
}()

env := os.Environ()
env = append(env, fmt.Sprintf("RESTIC_REPOSITORY=%s", c.repository.URL))
env = append(env, fmt.Sprintf("RESTIC_PASSWORD_FILE=%s", passwordFile))

// Helper function
func (c *Client) writeSecurePasswordFile(password string) (string, error) {
    file, err := os.CreateTemp(filepath.Dir(LocalPasswordDir), "restic-pw-*.tmp")
    if err != nil {
        return "", err
    }
    
    if _, err := file.WriteString(password); err != nil {
        file.Close()
        os.Remove(file.Name())
        return "", err
    }
    file.Close()
    
    // Restrict to owner only
    if err := os.Chmod(file.Name(), 0600); err != nil {
        os.Remove(file.Name())
        return "", err
    }
    
    return file.Name(), nil
}
```

---

## P0-2: Local Password Storage Fix

### Current (BROKEN):
```go
// pkg/backup/create.go lines 263-267
func storeLocalPassword(repoName, password string) error {
    // Store password in local secrets directory
    // Implementation would ensure proper permissions
    return nil  // ← DOES NOTHING
}
```

### Required Fix:
```go
func storeLocalPassword(repoName, password string) error {
    // Create secrets directory if needed
    if err := os.MkdirAll(LocalPasswordDir, 0700); err != nil {
        return fmt.Errorf("creating secrets directory: %w", err)
    }
    
    passwordFile := filepath.Join(LocalPasswordDir, fmt.Sprintf("%s.password", repoName))
    
    // Write with restricted permissions
    if err := os.WriteFile(passwordFile, []byte(password), LocalPasswordPerm); err != nil {
        return fmt.Errorf("writing local password file: %w", err)
    }
    
    return nil
}
```

---

## P0-3: Restore-to-Root Fix

### Current (DANGEROUS):
```go
// cmd/backup/restore.go lines 75-84
if target == "" {
    target = "/"  // ← SYSTEM ROOT!
    logger.Warn("No target specified...")
    if !force {
        return fmt.Errorf("restoring to original location requires --force")
    }
}
```

### Required Fix:
```go
// Default to safe temporary location
if target == "" {
    timestamp := time.Now().Format("20060102-150405")
    target = filepath.Join("/tmp", fmt.Sprintf("restore-%s", timestamp))
    logger.Info("Using default restore target",
        zap.String("target", target))
}

// Prevent accidental root restoration
if target == "/" || target == "/etc" {
    return fmt.Errorf("restoring to system directories is dangerous\n"+
        "Use --target /tmp/restore or similar\n"+
        "Or use --to-root to confirm system restore (requires --force)")
}

// Show user what will be restored before proceeding
snapshots, err := client.ListSnapshots()
if err != nil {
    return fmt.Errorf("listing snapshot contents: %w", err)
}
// Count files that will be restored
fileCount := 0
for _, snap := range snapshots {
    if snap.ID == snapshotID {
        fileCount = len(snap.Paths)
        break
    }
}

logger.Warn("About to restore snapshot",
    zap.String("snapshot", snapshotID),
    zap.String("target", target),
    zap.Int("file_count", fileCount))
```

---

## P0-4: Hook Whitelist Fix

### Current (BYPASSABLE):
```go
// pkg/backup/operations.go lines 74-105
allowedCommands := map[string]bool{
    "/usr/bin/restic": true,
    // ...
}

cmd := parts[0]
cleanCmd := filepath.Clean(cmd)  // ← Insufficient
allowed, exists := allowedCommands[cleanCmd]
```

### Required Fix:
```go
// Validate hook command comprehensively
func validateHookCommand(hookCmd string) error {
    parts := strings.Fields(hookCmd)
    if len(parts) == 0 {
        return fmt.Errorf("empty hook command")
    }
    
    cmd := parts[0]
    
    // 1. Must be absolute path
    if !filepath.IsAbs(cmd) {
        return fmt.Errorf("hook command must be absolute path, got: %s", cmd)
    }
    
    // 2. Resolve to real path (handles symlinks)
    realPath, err := filepath.EvalSymlinks(cmd)
    if err != nil {
        return fmt.Errorf("cannot resolve hook command: %w", err)
    }
    
    // 3. Check whitelist with resolved path
    allowedCommands := map[string]bool{
        "/usr/bin/restic": true,
        "/usr/bin/rsync": true,
        "/usr/bin/tar": true,
        "/usr/bin/gzip": true,
    }
    
    if !allowedCommands[realPath] {
        return fmt.Errorf("command not whitelisted: %s (resolved to %s)", cmd, realPath)
    }
    
    // 4. Validate arguments for injection
    for i, arg := range parts[1:] {
        // No shell metacharacters
        if strings.ContainsAny(arg, ";|&`$<>(){}[]'\"\\") {
            return fmt.Errorf("argument %d contains shell metacharacters", i+1)
        }
        // No path traversal
        if strings.Contains(arg, "..") {
            return fmt.Errorf("argument %d contains path traversal", i+1)
        }
    }
    
    return nil
}
```

---

## P0-5: Constants File Required

### Create: `/Users/henry/Dev/eos/pkg/backup/constants.go`

```go
package backup

import "os"

const (
    // Configuration paths
    BackupConfigPath = "/etc/eos/backup.yaml"
    BackupConfigDir  = "/etc/eos"
    
    // Secret storage paths
    LocalPasswordDir = "/var/lib/eos/secrets/backup"
    
    // File permissions with security rationale
    
    // BackupConfigPerm: Configuration file permissions
    // RATIONALE: Readable by eos user only, not world-readable
    // SECURITY: Prevents information disclosure of repository URLs
    // THREAT MODEL: Prevents unprivileged users from discovering backup infrastructure
    BackupConfigPerm = 0640
    
    // LocalPasswordPerm: Local password file permissions
    // RATIONALE: Owner-only read/write, no group or world access
    // SECURITY: Ensures only root/eos user can access backup encryption keys
    // THREAT MODEL: Prevents privilege escalation via password theft
    LocalPasswordPerm = 0600
    
    // PasswordFilePerm: Temporary password file permissions
    // RATIONALE: Owner-only read/write for temporary secrets
    // SECURITY: Minimal exposure window for decryption passwords
    PasswordFilePerm = 0600
    
    // BackupDirPerm: Backup directory permissions
    // RATIONALE: Standard UNIX directory permissions (owner rwx, group rx, world rx)
    // SECURITY: Allows directory traversal for services, prevents file read access
    BackupDirPerm = 0755
    
    // SecretsDirPerm: Secrets directory permissions
    // RATIONALE: Owner-only access, not traversable by others
    // SECURITY: Prevents any access to password/key storage
    SecretsDirPerm = 0700
)

// ResticMinVersion is the minimum supported restic version
const ResticMinVersion = "0.14.0"
```

Update all files to use these constants:

**pkg/backup/config.go:**
```go
// Before: if err := os.MkdirAll("/etc/eos", 0755); err != nil {
// After:
if err := os.MkdirAll(BackupConfigDir, BackupDirPerm); err != nil {
    return fmt.Errorf("creating config directory: %w", err)
}

// Before: configPath := "/etc/eos/backup.yaml"
// After:
configPath := BackupConfigPath
```

**pkg/backup/client.go:**
```go
// Before: passwordFile := fmt.Sprintf("/var/lib/eos/secrets/backup/%s.password", ...)
// After:
passwordFile := filepath.Join(LocalPasswordDir, fmt.Sprintf("%s.password", c.repository.Name))
```

---

## P1-1: Implement Real Assess/Intervene/Evaluate

### Current (FAKE):
```go
// pkg/backup/operations.go lines 214-215
prerequisites["repository_exists"] = true  // ← Never checked!
prerequisites["disk_space_available"] = true  // ← Never checked!
```

### Required Fix:
```go
func (b *BackupOperation) Assess(ctx context.Context) (*patterns.AssessmentResult, error) {
    b.Logger.Info("Assessing backup readiness",
        zap.String("profile", b.ProfileName),
        zap.String("repository", b.RepoName))
    
    prerequisites := make(map[string]bool)
    
    // Check 1: Repository exists
    client, err := NewClient(b.rc, b.RepoName)
    if err != nil {
        return &patterns.AssessmentResult{
            CanProceed: false,
            Reason: fmt.Sprintf("repository %q not found: %v", b.RepoName, err),
            Prerequisites: map[string]bool{"repository_exists": false},
        }, nil
    }
    prerequisites["repository_exists"] = true
    
    // Check 2: Repository is accessible
    if _, err := client.ListSnapshots(); err != nil {
        return &patterns.AssessmentResult{
            CanProceed: false,
            Reason: fmt.Sprintf("repository not accessible: %v", err),
            Prerequisites: prerequisites,
        }, nil
    }
    prerequisites["repository_accessible"] = true
    
    // Check 3: All paths exist
    for _, path := range b.Profile.Paths {
        if _, err := os.Stat(path); err != nil {
            prerequisites[fmt.Sprintf("path_exists_%s", path)] = false
            return &patterns.AssessmentResult{
                CanProceed: false,
                Reason: fmt.Sprintf("backup path does not exist: %s", path),
                Prerequisites: prerequisites,
            }, nil
        }
        prerequisites[fmt.Sprintf("path_exists_%s", path)] = true
    }
    
    // Check 4: Disk space available
    // Get total size of paths to backup
    totalSize := int64(0)
    for _, path := range b.Profile.Paths {
        size, err := getDirSize(path)
        if err != nil {
            b.Logger.Warn("Could not determine directory size",
                zap.String("path", path),
                zap.Error(err))
            continue
        }
        totalSize += size
    }
    
    // Check available disk space (need 20% buffer for restic)
    var stat syscall.Statfs_t
    if err := syscall.Statfs(b.Profile.Paths[0], &stat); err == nil {
        availableSpace := int64(stat.Bavail) * int64(stat.Bsize)
        requiredSpace := totalSize / 5  // 20% buffer
        if availableSpace < requiredSpace {
            prerequisites["disk_space_available"] = false
            return &patterns.AssessmentResult{
                CanProceed: false,
                Reason: fmt.Sprintf("insufficient disk space: need %d MB, have %d MB",
                    requiredSpace/1024/1024, availableSpace/1024/1024),
                Prerequisites: prerequisites,
            }, nil
        }
    }
    prerequisites["disk_space_available"] = true
    
    return &patterns.AssessmentResult{
        CanProceed: true,
        Prerequisites: prerequisites,
        Context: map[string]interface{}{
            "paths_count": len(b.Profile.Paths),
            "tags_count": len(b.Profile.Tags),
            "total_size_bytes": totalSize,
        },
    }, nil
}

// Helper function
func getDirSize(path string) (int64, error) {
    var size int64
    err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
        if err != nil {
            return nil // Skip inaccessible files
        }
        if !info.IsDir() {
            size += info.Size()
        }
        return nil
    })
    return size, err
}
```

---

## P1-2: Move Restore Logic to pkg/

### Current (WRONG):
File: `/Users/henry/Dev/eos/cmd/backup/restore.go` (184 lines with business logic)

### Required Fix:

Create: `/Users/henry/Dev/eos/pkg/backup/restore.go`

```go
package backup

import (
    "fmt"
    "os"
    "path/filepath"
    "time"
    "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
    "github.com/uptrace/opentelemetry-go-extra/otelzap"
    "go.uber.org/zap"
)

type RestoreOptions struct {
    SnapshotID string
    Target     string
    Includes   []string
    Excludes   []string
    Verify     bool
    Force      bool
    DryRun     bool
}

func Restore(rc *eos_io.RuntimeContext, repoName string, opts *RestoreOptions) error {
    logger := otelzap.Ctx(rc.Ctx)
    
    logger.Info("Starting restore operation",
        zap.String("snapshot", opts.SnapshotID),
        zap.String("repository", repoName),
        zap.String("target", opts.Target))
    
    // Validate target location
    if err := validateRestoreTarget(opts.Target, opts.Force); err != nil {
        return err
    }
    
    // Create client
    client, err := NewClient(rc, repoName)
    if err != nil {
        return fmt.Errorf("creating backup client: %w", err)
    }
    
    // Perform restore
    if err := client.Restore(opts.SnapshotID, opts.Target); err != nil {
        return fmt.Errorf("restore failed: %w", err)
    }
    
    // Fix permissions on restored files
    if err := fixRestoredPermissions(logger, opts.Target); err != nil {
        logger.Warn("Failed to fix some permissions", zap.Error(err))
    }
    
    logger.Info("Restore completed successfully")
    return nil
}

func validateRestoreTarget(target string, force bool) error {
    // Default to safe location
    if target == "" {
        timestamp := time.Now().Format("20060102-150405")
        target = filepath.Join("/tmp", fmt.Sprintf("restore-%s", timestamp))
    }
    
    // Prevent system restoration by accident
    if target == "/" || target == "/etc" {
        if !force {
            return fmt.Errorf("restoring to system directory requires --to-root --force")
        }
    }
    
    return nil
}

func fixRestoredPermissions(logger otelzap.LoggerWithCtx, target string) error {
    return filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return nil
        }
        if info.IsDir() {
            return os.Chmod(path, info.Mode()|0700)
        }
        return nil
    })
}
```

Update: `/Users/henry/Dev/eos/cmd/backup/restore.go` (reduce to ~50 lines):

```go
// ... flag parsing only ...
RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    logger := otelzap.Ctx(rc.Ctx)
    snapshotID := args[0]
    repoName, _ := cmd.Flags().GetString("repo")
    target, _ := cmd.Flags().GetString("target")
    includes, _ := cmd.Flags().GetStringSlice("include")
    excludes, _ := cmd.Flags().GetStringSlice("exclude")
    verify, _ := cmd.Flags().GetBool("verify")
    force, _ := cmd.Flags().GetBool("force")
    
    if repoName == "" {
        config, err := backup.LoadConfig(rc)
        if err != nil {
            return fmt.Errorf("loading configuration: %w", err)
        }
        repoName = config.DefaultRepository
        if repoName == "" {
            return fmt.Errorf("no repository specified and no default configured")
        }
    }
    
    opts := &backup.RestoreOptions{
        SnapshotID: snapshotID,
        Target: target,
        Includes: includes,
        Excludes: excludes,
        Verify: verify,
        Force: force,
    }
    
    return backup.Restore(rc, repoName, opts)
}),
```

---

## Testing Required

Create: `/Users/henry/Dev/eos/pkg/backup/restore_test.go`

```go
func TestRestoreValidation(t *testing.T) {
    tests := []struct {
        name    string
        target  string
        force   bool
        wantErr bool
    }{
        {"empty target", "", false, false},
        {"safe target", "/tmp/restore", false, false},
        {"root without force", "/", false, true},
        {"root with force", "/", true, false},
        {"/etc without force", "/etc", false, true},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := validateRestoreTarget(tt.target, tt.force)
            if (err != nil) != tt.wantErr {
                t.Errorf("validateRestoreTarget() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}
```


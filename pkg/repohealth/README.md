# pkg/repohealth

*Last Updated: 2026-03-14*

Repository health checks for Eos development environments.

## Purpose

Detects and reports file ownership issues that cause git operations to fail with "Permission denied" errors. This is a common problem when commands run as root (via `sudo go test`, `sudo make`, Docker operations) in a user-owned repository.

## Usage

### Go API

```go
report, err := repohealth.AuditOwnership("/opt/eos")
if err != nil {
    log.Fatal(err)
}
if report.HasIssues() {
    fmt.Println(report.Summary())
    // Output includes the fix command: sudo chown -R user:user /opt/eos
}
```

### Quick Check (Fast Path)

```go
hasIssues, err := repohealth.QuickCheck("/opt/eos")
```

### npm Script

```bash
npm run repo:check    # Check ownership
npm run repo:fix      # Fix ownership (requires sudo)
```

## Root Cause

POSIX file system semantics: file deletion/creation is controlled by the parent directory's write+execute permission, not the file's own permissions. When `sudo` creates files, both the file AND its parent directory may become root-owned, preventing the repo owner from modifying them.

## Testing

```bash
go test -v ./pkg/repohealth/...
```

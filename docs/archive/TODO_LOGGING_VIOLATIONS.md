# TODO: Fix Logging Violations in pkg/

According to CLAUDE.md, all code must use structured logging with `otelzap.Ctx(rc.Ctx)` and NEVER use `fmt.Printf`, `fmt.Println`, or `fmt.Print` for output.

## Files with Logging Violations

### High Priority (Core Infrastructure)
- [ ] **pkg/eos_unix/systemctl.go** - 3 violations (lines 122, 129-130)
- [ ] **pkg/eos_unix/permissions.go** - 3 violations (lines 65, 99, 110)
- [ ] **pkg/eos_unix/user.go** - 5 violations (lines 68, 79, 97, 235-237, 247)
- [ ] **pkg/eos_unix/interaction.go** - 1 violation (line 18)
- [ ] **pkg/eos_io/secure_input.go** - 2 violations (lines 24, 26)
- [ ] **pkg/execute/execute.go** - 2 violations (lines 149, 159)
- [ ] **pkg/execute/retry.go** - 4 violations (lines 21, 31, 53, 60)
- [ ] **pkg/logger/lifecycle.go** - 2 violations (lines 57, 63)
- [ ] **pkg/logger/print.go** - 1 violation (line 16)
- [ ] **pkg/privilege_check/manager.go** - 3 violations (lines 233-235, 238)

### Service Management
- [ ] **pkg/shared/service_management.go** - 3 violations (lines 338, 354, 371)
- [ ] **pkg/system_services/manager.go** - 1 violation (line 347)
- [ ] **pkg/service_installation/grafana.go** - 5 violations (lines 42, 46, 55, 64, 80)

### Platform/Infrastructure
- [ ] **pkg/platform/firewall.go** - 3 violations (lines 40, 48, 59)
- [ ] **pkg/kvm/lifecycle.go** - 3 violations (lines 38, 47, 54)
- [ ] **pkg/kvm/print.go** - 3 violations (lines 18, 20, 31)
- [ ] **pkg/kvm/network.go** - 3 violations (lines 34, 67, 99)
- [ ] **pkg/kvm/libvirt.go** - 2 violations (lines 12, 20)
- [ ] **pkg/kubernetes/k3s.go** - 39 violations (extensive use throughout file)
- [ ] **pkg/container/helper.go** - 5 violations (lines 54, 61, 69, 78, 87)
- [ ] **pkg/container/containers.go** - 3 violations (lines 31, 81, 88)
- [ ] **pkg/nginx/nginx.go** - 4 violations (lines 24, 71, 80, 96)

### Security/Authentication
- [ ] **pkg/ubuntu/mfa_users.go** - 43 violations (lines 628-684, extensive output)
- [ ] **pkg/ubuntu/mfa_enforced.go** - 1 violation (line 539)
- [ ] **pkg/ubuntu/secure_enhanced.go** - 50+ violations (lines 124-221, extensive output)
- [ ] **pkg/ldap/reader.go** - 3 violations (lines 72, 105, 153, 160)
- [ ] **pkg/ldap/lifecycle.go** - 2 violations (lines 18, 36)
- [ ] **pkg/ldap/print.go** - 3 violations (lines 17, 19, 30)
- [ ] **pkg/ldap/modify.go** - 3 violations (lines 20, 48, 78)
- [ ] **pkg/ldap/writer.go** - 1 violation (line 21)
- [ ] **pkg/crypto/prompt.go** - 2 violations (lines 23, 38)

### Application/Services
- [ ] **pkg/application/config.go** - 6 violations (lines 52, 63, 87, 108, 114)
- [ ] **pkg/wazuh/docker/credentials.go** - 5 violations (lines 27, 33, 39, 45)
- [ ] **pkg/wazuh/docker/deployment.go** - 4 violations (lines 35, 41, 56, 71)
- [ ] **pkg/helen/manager.go** - 2 violations (lines 164, 166)
- [ ] **pkg/hecate/config.go** - 1 violation (line 111)
- [ ] **pkg/ai/config.go** - 1 violation (line 408)

### Data Management
- [ ] **pkg/vault/util_delete.go** - 1 violation (line 21)
- [ ] **pkg/vault/util_fallback.go** - 1 violation (line 84)
- [ ] **pkg/vault/export_display.go** - 1 violation (line 45)
- [ ] **pkg/database_management/authc.go** - 11 violations (lines 30, 41, 58, 69, 83, 94, 108, 119, 130, 164)

### Utilities
- [ ] **pkg/command/installer.go** - 3 violations (lines 98, 115, 132)
- [ ] **pkg/users/management.go** - 1 violation (line 433)
- [ ] **pkg/pipeline/alerts/display.go** - 1 violation (line 22)
- [ ] **pkg/pipeline/monitor/display.go** - 1 violation (line 24)
- [ ] **pkg/ragequit/emergency/confirmation.go** - 7 violations (lines 30-37)

## Implementation Notes

1. All `fmt.Print*` calls should be replaced with structured logging using `otelzap.Ctx(rc.Ctx)`
2. For user prompts, use `logger.Info("terminal prompt: [question]")` before reading input
3. For progress/status messages, use appropriate log levels (Info, Debug)
4. For error messages shown to users, use `eos_err.NewUserError()` or `eos_err.NewSystemError()`
5. Ensure all functions receive `*eos_io.RuntimeContext` to access the logger

## Priority Order

1. Start with core infrastructure packages (eos_unix, eos_io, execute)
2. Then fix service management and platform packages
3. Finally address application-specific packages

## Example Transformation

### Before:
```go
fmt.Println("Installing package...")
fmt.Printf("Package %s installed\n", pkgName)
```

### After:
```go
logger := otelzap.Ctx(rc.Ctx)
logger.Info("Installing package")
logger.Info("Package installed successfully", zap.String("package", pkgName))
```
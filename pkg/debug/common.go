// pkg/debug/common.go
// Common diagnostic utilities usable across all services

package debug

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// BinaryCheck creates a diagnostic that checks if a binary exists and is executable
func BinaryCheck(name, path string) *Diagnostic {
	return &Diagnostic{
		Name:        fmt.Sprintf("%s Binary", name),
		Category:    "Installation",
		Description: fmt.Sprintf("Check if %s binary exists and is executable", name),
		Collect: func(ctx context.Context) (*Result, error) {
			result := &Result{
				Metadata: make(map[string]interface{}),
			}

			info, err := os.Stat(path)
			if err != nil {
				if os.IsNotExist(err) {
					result.Status = StatusError
					result.Message = "Binary not found"
					result.Remediation = fmt.Sprintf("Install %s binary at %s", name, path)
					result.Metadata["path"] = path
					result.Metadata["exists"] = false
					return result, nil
				}
				return result, err
			}

			result.Metadata["path"] = path
			result.Metadata["exists"] = true
			result.Metadata["size"] = info.Size()
			result.Metadata["mode"] = info.Mode().String()
			result.Metadata["modified"] = info.ModTime()

			// Check if executable
			if info.Mode().Perm()&0111 == 0 {
				result.Status = StatusError
				result.Message = "Binary exists but not executable"
				result.Remediation = fmt.Sprintf("chmod +x %s", path)
				return result, nil
			}

			// Try to get version
			cmd := exec.CommandContext(ctx, path, "version")
			output, err := cmd.CombinedOutput()
			if err == nil {
				result.Output = string(output)
				result.Metadata["version"] = strings.TrimSpace(string(output))
			}

			result.Status = StatusOK
			result.Message = "Binary found and executable"
			return result, nil
		},
	}
}

// FileCheck creates a diagnostic that checks if a file exists and shows its contents
func FileCheck(name, path string, showContents bool) *Diagnostic {
	return &Diagnostic{
		Name:        name,
		Category:    "Configuration",
		Description: fmt.Sprintf("Check file %s", path),
		Collect: func(ctx context.Context) (*Result, error) {
			result := &Result{
				Metadata: make(map[string]interface{}),
			}

			info, err := os.Stat(path)
			if err != nil {
				if os.IsNotExist(err) {
					result.Status = StatusWarning
					result.Message = "File not found"
					result.Metadata["path"] = path
					result.Metadata["exists"] = false
					return result, nil
				}
				return result, err
			}

			result.Metadata["path"] = path
			result.Metadata["exists"] = true
			result.Metadata["size"] = info.Size()
			result.Metadata["mode"] = info.Mode().String()
			result.Metadata["modified"] = info.ModTime()

			if showContents && info.Size() > 0 && info.Size() < 1024*100 { // Only show files < 100KB
				data, err := os.ReadFile(path)
				if err == nil {
					result.Output = string(data)
				}
			}

			result.Status = StatusOK
			result.Message = fmt.Sprintf("File found (%d bytes)", info.Size())
			return result, nil
		},
	}
}

// DirectoryCheck creates a diagnostic that checks if a directory exists with proper permissions
func DirectoryCheck(name, path string, expectedUser string) *Diagnostic {
	return &Diagnostic{
		Name:        name,
		Category:    "Filesystem",
		Description: fmt.Sprintf("Check directory %s", path),
		Collect: func(ctx context.Context) (*Result, error) {
			result := &Result{
				Metadata: make(map[string]interface{}),
			}

			info, err := os.Stat(path)
			if err != nil {
				if os.IsNotExist(err) {
					result.Status = StatusError
					result.Message = "Directory not found"
					result.Remediation = fmt.Sprintf("Create directory: mkdir -p %s", path)
					result.Metadata["path"] = path
					result.Metadata["exists"] = false
					return result, nil
				}
				return result, err
			}

			if !info.IsDir() {
				result.Status = StatusError
				result.Message = "Path exists but is not a directory"
				result.Metadata["path"] = path
				result.Metadata["is_dir"] = false
				return result, nil
			}

			result.Metadata["path"] = path
			result.Metadata["exists"] = true
			result.Metadata["is_dir"] = true
			result.Metadata["mode"] = info.Mode().String()
			result.Metadata["modified"] = info.ModTime()

			// List contents
			entries, err := os.ReadDir(path)
			if err == nil {
				result.Metadata["entry_count"] = len(entries)
				var fileList []string
				for i, entry := range entries {
					if i < 10 { // Only show first 10
						fileList = append(fileList, entry.Name())
					}
				}
				if len(fileList) > 0 {
					result.Output = fmt.Sprintf("Contents (showing %d of %d):\n%s",
						len(fileList), len(entries), strings.Join(fileList, "\n"))
				}
			}

			result.Status = StatusOK
			result.Message = fmt.Sprintf("Directory exists with %d entries", len(entries))
			return result, nil
		},
	}
}

// SystemdServiceCheck creates a diagnostic that checks systemd service status
func SystemdServiceCheck(serviceName string) *Diagnostic {
	return &Diagnostic{
		Name:        fmt.Sprintf("%s Service", serviceName),
		Category:    "Systemd",
		Description: fmt.Sprintf("Check systemd service %s", serviceName),
		Collect: func(ctx context.Context) (*Result, error) {
			result := &Result{
				Metadata: make(map[string]interface{}),
			}

			// Check if service unit file exists
			unitPath := fmt.Sprintf("/etc/systemd/system/%s.service", serviceName)
			if _, err := os.Stat(unitPath); os.IsNotExist(err) {
				result.Status = StatusError
				result.Message = "Service unit file not found"
				result.Metadata["unit_path"] = unitPath
				result.Metadata["exists"] = false
				return result, nil
			}

			// Get service status
			cmd := exec.CommandContext(ctx, "systemctl", "status", serviceName, "--no-pager", "-l")
			output, err := cmd.CombinedOutput()
			result.Output = string(output)

			// Check if active
			cmd = exec.CommandContext(ctx, "systemctl", "is-active", serviceName)
			isActive, _ := cmd.CombinedOutput()
			active := strings.TrimSpace(string(isActive)) == "active"
			result.Metadata["active"] = active

			// Check if enabled
			cmd = exec.CommandContext(ctx, "systemctl", "is-enabled", serviceName)
			isEnabled, _ := cmd.CombinedOutput()
			enabled := strings.TrimSpace(string(isEnabled)) == "enabled"
			result.Metadata["enabled"] = enabled

			if active {
				result.Status = StatusOK
				result.Message = "Service is running"
			} else {
				result.Status = StatusError
				result.Message = "Service is not running"
				result.Remediation = fmt.Sprintf("systemctl start %s", serviceName)

				// Get recent logs
				logCmd := exec.CommandContext(ctx, "journalctl", "-u", serviceName, "-n", "50", "--no-pager")
				logOutput, _ := logCmd.CombinedOutput()
				if len(logOutput) > 0 {
					result.Output += "\n\n=== Recent Logs ===\n" + string(logOutput)
				}
			}

			return result, err
		},
	}
}

// CommandCheck runs a command and reports the output
func CommandCheck(name, category string, cmd string, args ...string) *Diagnostic {
	return &Diagnostic{
		Name:        name,
		Category:    category,
		Description: fmt.Sprintf("Run command: %s %s", cmd, strings.Join(args, " ")),
		Collect: func(ctx context.Context) (*Result, error) {
			result := &Result{
				Metadata: make(map[string]interface{}),
			}

			execCmd := exec.CommandContext(ctx, cmd, args...)
			output, err := execCmd.CombinedOutput()

			result.Output = string(output)
			result.Metadata["command"] = fmt.Sprintf("%s %s", cmd, strings.Join(args, " "))
			result.Metadata["exit_code"] = execCmd.ProcessState.ExitCode()

			if err != nil {
				result.Status = StatusWarning
				result.Message = fmt.Sprintf("Command failed: %v", err)
			} else {
				result.Status = StatusInfo
				result.Message = "Command executed successfully"
			}

			return result, nil
		},
	}
}

// NetworkCheck tests network connectivity
func NetworkCheck(name, address string, timeout time.Duration) *Diagnostic {
	return &Diagnostic{
		Name:        name,
		Category:    "Network",
		Description: fmt.Sprintf("Test connectivity to %s", address),
		Collect: func(ctx context.Context) (*Result, error) {
			result := &Result{
				Metadata: make(map[string]interface{}),
			}

			result.Metadata["address"] = address
			result.Metadata["timeout"] = timeout.String()

			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			cmd := exec.CommandContext(ctx, "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", address)
			output, err := cmd.CombinedOutput()

			httpCode := strings.TrimSpace(string(output))
			result.Metadata["http_code"] = httpCode

			if err != nil {
				result.Status = StatusError
				result.Message = fmt.Sprintf("Connection failed: %v", err)
				result.Remediation = fmt.Sprintf("Check network connectivity and firewall rules for %s", address)
			} else if httpCode == "200" || httpCode == "000" { // 000 = connection successful but no HTTP response
				result.Status = StatusOK
				result.Message = "Connection successful"
			} else {
				result.Status = StatusWarning
				result.Message = fmt.Sprintf("Connection successful but received HTTP %s", httpCode)
			}

			return result, nil
		},
	}
}

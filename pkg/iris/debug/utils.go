// pkg/iris/debug/utils.go
package debug

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DisplayDiagnosticResults displays a formatted report of all diagnostic check results
func DisplayDiagnosticResults(results []CheckResult, verbose bool) {
	// Count passed/failed by category
	passed := 0
	failed := 0
	categoryMap := make(map[string][]CheckResult)

	for _, r := range results {
		if r.Passed {
			passed++
		} else {
			failed++
		}
		categoryMap[r.Category] = append(categoryMap[r.Category], r)
	}

	total := passed + failed

	// Header
	fmt.Println()
	fmt.Println("╔════════════════════════════════════════════════════════════════╗")
	fmt.Println("║              IRIS DIAGNOSTIC REPORT                           ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Summary
	status := "HEALTHY"
	if failed > 0 {
		status = "ISSUES DETECTED"
	}

	fmt.Printf("Status: %s\n", status)
	fmt.Printf("Passed: %d/%d checks\n", passed, total)
	if failed > 0 {
		fmt.Printf("Failed: %d checks\n", failed)
	}
	fmt.Println()

	// Group results by category
	categories := []string{"Infrastructure", "Configuration", "Services", "Dependencies"}

	for _, category := range categories {
		checks := categoryMap[category]
		if len(checks) == 0 {
			continue
		}

		fmt.Printf("┌─ %s\n", category)
		for _, check := range checks {
			if check.Passed {
				fmt.Printf("│  ✓ %s\n", check.Name)
				// Show details if verbose OR if details contain structured info
				if check.Details != "" && (verbose || strings.Contains(check.Details, "✓") || strings.Contains(check.Details, "✗")) {
					// Indent multi-line details
					detailLines := strings.Split(check.Details, "\n")
					for _, line := range detailLines {
						if line != "" {
							fmt.Printf("│    %s\n", line)
						}
					}
				}
			} else {
				fmt.Printf("│  ✗ %s\n", check.Name)
			}
		}
		fmt.Println("│")
	}

	// Show failures with remediation
	if failed > 0 {
		fmt.Println()
		fmt.Println("╔════════════════════════════════════════════════════════════════╗")
		fmt.Println("║                   ISSUES & REMEDIATION                         ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════╝")
		fmt.Println()

		issueNum := 1
		for _, r := range results {
			if !r.Passed {
				fmt.Printf("Issue %d: %s\n", issueNum, r.Name)
				fmt.Printf("Problem: %v\n", r.Error)

				// Show details if available
				if r.Details != "" {
					fmt.Println()
					fmt.Println("Details:")
					detailLines := strings.Split(r.Details, "\n")
					for _, line := range detailLines {
						if line != "" {
							fmt.Printf("  %s\n", line)
						}
					}
				}

				fmt.Println()
				fmt.Println("Solutions:")
				for _, remedy := range r.Remediation {
					fmt.Printf("  • %s\n", remedy)
				}
				fmt.Println()
				issueNum++
			}
		}

		// Next steps summary
		fmt.Println("╔════════════════════════════════════════════════════════════════╗")
		fmt.Println("║                        NEXT STEPS                              ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════╝")
		fmt.Println()
		fmt.Println("Recommended action order:")
		fmt.Println()

		step := 1
		// Infrastructure first
		for _, r := range results {
			if !r.Passed && r.Category == "Infrastructure" {
				fmt.Printf("%d. Fix: %s\n", step, r.Name)
				step++
			}
		}
		// Then configuration
		for _, r := range results {
			if !r.Passed && r.Category == "Configuration" {
				fmt.Printf("%d. Fix: %s\n", step, r.Name)
				step++
			}
		}
		// Then services
		for _, r := range results {
			if !r.Passed && r.Category == "Services" {
				fmt.Printf("%d. Fix: %s\n", step, r.Name)
				step++
			}
		}
		// Finally dependencies
		for _, r := range results {
			if !r.Passed && r.Category == "Dependencies" {
				fmt.Printf("%d. Fix: %s\n", step, r.Name)
				step++
			}
		}
		fmt.Println()
		fmt.Println("After fixing issues, run: eos debug iris")
		fmt.Println()
	} else {
		fmt.Println("╔════════════════════════════════════════════════════════════════╗")
		fmt.Println("║                  ALL CHECKS PASSED                             ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════╝")
		fmt.Println()
		fmt.Println("Iris is configured and operational.")
		fmt.Println()
		fmt.Println("To test the alert processing pipeline:")
		fmt.Println("  eos debug iris --test")
		fmt.Println()
		fmt.Println("To view Temporal workflows:")
		fmt.Println("  • Open http://localhost:8233")
		fmt.Println("  • Or use: temporal workflow list")
		fmt.Println()
	}
}

// FindTemporalBinary searches for the Temporal binary in common locations and provides diagnostics
func FindTemporalBinary(rc *eos_io.RuntimeContext) string {
	logger := otelzap.Ctx(rc.Ctx)
	var findings []string

	// Check common installation locations
	commonPaths := []string{
		"/usr/local/bin/temporal",
		"/usr/bin/temporal",
		os.ExpandEnv("$HOME/.local/bin/temporal"),
		os.ExpandEnv("$HOME/.temporalio/bin/temporal"), // Official installer location
		"/root/.temporalio/bin/temporal",               // Root user installation
		"/opt/temporal/temporal",
	}

	for _, path := range commonPaths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			findings = append(findings, fmt.Sprintf("✓ Found at: %s", path))

			// Check if executable
			if info.Mode()&0111 == 0 {
				findings = append(findings, "  ✗ NOT EXECUTABLE")
				findings = append(findings, fmt.Sprintf("  Fix: sudo chmod +x %s", path))
			} else {
				// Binary is executable - check if it's in PATH
				pathEnv := os.Getenv("PATH")
				binaryDir := filepath.Dir(path)
				inPath := false

				for _, dir := range strings.Split(pathEnv, ":") {
					if dir == binaryDir {
						inPath = true
						break
					}
				}

				if !inPath {
					findings = append(findings, fmt.Sprintf("  ✗ NOT IN PATH (directory %s not in PATH)", binaryDir))
					findings = append(findings, "  This is why 'temporal' command is not found!")
					findings = append(findings, "")
					findings = append(findings, "  Quick Fix (works immediately): Create symlink")
					findings = append(findings, fmt.Sprintf("    sudo ln -s %s /usr/local/bin/temporal", path))
					findings = append(findings, "")
					findings = append(findings, "  Permanent Fix (survives reboots): Add to PATH")

					// Detect shell and provide appropriate config file
					shell := os.Getenv("SHELL")
					configFile := "~/.bashrc"
					if strings.Contains(shell, "zsh") {
						configFile = "~/.zshrc"
					}

					findings = append(findings, fmt.Sprintf("    echo 'export PATH=\"%s:$PATH\"' >> %s", binaryDir, configFile))
					findings = append(findings, fmt.Sprintf("    source %s", configFile))
					findings = append(findings, "")
					findings = append(findings, "  Alternative: Move binary to system location")
					findings = append(findings, fmt.Sprintf("    sudo mv %s /usr/local/bin/temporal", path))
				} else {
					findings = append(findings, "  ✓ Binary is in PATH and executable")
				}
			}

			logger.Debug("Found temporal binary", zap.String("path", path), zap.Uint32("mode", uint32(info.Mode())))
		}
	}

	// Search /tmp and /var/tmp for downloaded but not installed binaries
	tmpDirs := []string{"/tmp", "/var/tmp"}
	for _, tmpDir := range tmpDirs {
		findCmd := exec.CommandContext(rc.Ctx, "find", tmpDir, "-name", "*temporal*", "-type", "f", "-maxdepth", "2")
		if output, err := findCmd.Output(); err == nil && len(output) > 0 {
			tmpFiles := strings.Split(strings.TrimSpace(string(output)), "\n")
			if len(tmpFiles) > 0 && tmpFiles[0] != "" {
				findings = append(findings, fmt.Sprintf("Temporary files found in %s:", tmpDir))
				for _, file := range tmpFiles {
					if file != "" {
						findings = append(findings, fmt.Sprintf("  %s", file))
					}
				}
				findings = append(findings, "  These may be incomplete downloads or extracted archives")
			}
		}
	}

	// Check system-wide search (only if nothing found yet and running as root)
	if len(findings) == 0 && os.Geteuid() == 0 {
		logger.Debug("Running limited system-wide search for temporal binary")
		// Search specific locations with timeout to avoid hanging
		ctx, cancel := context.WithTimeout(rc.Ctx, 5*time.Second)
		defer cancel()

		// Search specific directories likely to contain binaries
		searchDirs := []string{"/usr", "/opt", "/root"}
		for _, searchDir := range searchDirs {
			findCmd := exec.CommandContext(ctx, "find", searchDir,
				"-maxdepth", "4", // Limit depth FIRST
				"-name", "temporal",
				"-type", "f",
				"-not", "-path", "*/.*",
				"-not", "-path", "*/go/pkg/*")

			if output, err := findCmd.Output(); err == nil && len(output) > 0 {
				systemFiles := strings.Split(strings.TrimSpace(string(output)), "\n")
				if len(systemFiles) > 0 && systemFiles[0] != "" {
					findings = append(findings, fmt.Sprintf("System-wide search found in %s:", searchDir))
					for _, file := range systemFiles {
						if file != "" && !strings.Contains(file, "/go/pkg/") {
							findings = append(findings, fmt.Sprintf("  %s", file))
						}
					}
				}
			}
			if ctx.Err() != nil {
				logger.Debug("System search timed out", zap.String("dir", searchDir))
				break
			}
		}
	}

	// Check PATH environment variable
	pathEnv := os.Getenv("PATH")
	if pathEnv != "" {
		findings = append(findings, fmt.Sprintf("Current PATH: %s", pathEnv))
	}

	// Check EOS installation logs for Temporal installation attempts
	logPath := "/var/log/eos/eos.log"
	if _, err := os.Stat(logPath); err == nil {
		// Use simpler approach: grep then take last N lines
		grepCmd := exec.CommandContext(rc.Ctx, "sh", "-c",
			fmt.Sprintf("grep -i temporal %s 2>/dev/null | tail -10 || true", logPath))

		if output, err := grepCmd.Output(); err == nil && len(output) > 0 {
			logLines := strings.Split(strings.TrimSpace(string(output)), "\n")
			if len(logLines) > 0 && logLines[0] != "" {
				findings = append(findings, "", "Recent Temporal-related log entries:")
				for _, line := range logLines {
					if line != "" {
						// Truncate very long lines
						if len(line) > 120 {
							line = line[:117] + "..."
						}
						findings = append(findings, fmt.Sprintf("  %s", line))
					}
				}
			}
		}
	}

	if len(findings) == 0 {
		return ""
	}

	return strings.Join(findings, "\n  ")
}

// SendTestAlert sends a test alert to the Iris webhook server
func SendTestAlert(rc *eos_io.RuntimeContext, config *IrisConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	if config == nil {
		return fmt.Errorf("config not loaded")
	}

	testAlert := map[string]interface{}{
		"agent": map[string]string{
			"name": "test-server",
			"id":   "001",
		},
		"data": map[string]interface{}{
			"vulnerability": map[string]interface{}{
				"severity": "High",
				"package": map[string]string{
					"name": "test-package",
				},
				"title": "TEST: Iris diagnostic test alert",
			},
		},
	}

	alertJSON, err := json.Marshal(testAlert)
	if err != nil {
		return fmt.Errorf("failed to marshal test alert: %w", err)
	}

	webhookURL := fmt.Sprintf("http://localhost:%d/webhook", config.Webhook.Port)
	logger.Info("Sending test alert", zap.String("url", webhookURL))

	ctx, cancel := context.WithTimeout(rc.Ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", webhookURL, strings.NewReader(string(alertJSON)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send test alert: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	logger.Info("Test alert sent successfully - check Temporal UI and email")
	return nil
}

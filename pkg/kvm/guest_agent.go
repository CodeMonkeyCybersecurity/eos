//go:build linux

// pkg/kvm/guest_agent.go
// QEMU Guest Agent management functions

package kvm

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"libvirt.org/go/libvirt"
)

// auditGuestExecChange logs guest-exec configuration changes for audit trail
func auditGuestExecChange(vmName, action, method, result string) {
	// Get current user
	currentUser := "unknown"
	if u, err := user.Current(); err == nil {
		currentUser = u.Username
	}

	// Prepare audit entry
	timestamp := time.Now().Format(time.RFC3339)
	entry := fmt.Sprintf("%s vm=%s action=%s user=%s method=%s result=%s\n",
		timestamp, vmName, action, currentUser, method, result)

	// Ensure audit log directory exists
	logDir := "/var/log/eos/audit"
	_ = os.MkdirAll(logDir, shared.ServiceDirPerm)

	// Append to audit log
	logFile := filepath.Join(logDir, "guest-exec.log")
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		// If we can't write to /var/log/eos/audit, try local directory
		logFile = "eos-guest-exec-audit.log"
		f, err = os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			// Audit logging failed, but don't fail the operation
			return
		}
	}
	defer func() { _ = f.Close() }()

	_, _ = f.WriteString(entry)
}

// EnableGuestExec enables guest-exec commands in QEMU guest agent
// This allows eos to run monitoring commands inside the VM
func EnableGuestExec(rc *eos_io.RuntimeContext, vmName string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Enabling guest-exec for VM",
		zap.String("vm", vmName))

	// Connect to libvirt
	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	defer func() { _, _ = conn.Close() }()

	// Get domain
	domain, err := conn.LookupDomainByName(vmName)
	if err != nil {
		return fmt.Errorf("failed to find VM: %w", err)
	}
	defer func() { _ = domain.Free() }()

	// Check if VM is running
	state, _, err := domain.GetState()
	if err != nil {
		return fmt.Errorf("failed to get VM state: %w", err)
	}

	if state != libvirt.DOMAIN_RUNNING {
		return fmt.Errorf("VM is not running (state: %s)", stateToString(state))
	}

	// Step 1: Check guest agent availability
	logger.Info("Checking guest agent availability")
	if !checkGuestAgent(domain) {
		return fmt.Errorf("guest agent is not responding - ensure qemu-guest-agent is installed and running in the VM")
	}

	// Step 2: Detect OS to determine config file path and format
	logger.Info("Detecting guest OS")
	osInfo := getVMOSInfo(domain)
	if osInfo == "" {
		return fmt.Errorf("failed to detect guest OS")
	}

	logger.Info("Detected OS", zap.String("os", osInfo))

	// Step 3: Check current status
	logger.Info("Checking current guest-exec status")
	beforeStatus := testGuestExec(domain)
	logger.Info("Current status",
		zap.String("before", beforeStatus))

	if beforeStatus == "ENABLED" {
		logger.Info("✓ guest-exec is already enabled")
		fmt.Println("✓ guest-exec is already enabled")
		return nil
	}

	// Step 4: Enable guest-exec based on OS
	logger.Info("Configuring guest agent to enable guest-exec")

	var configFile, configContent, restartCmd string

	if strings.Contains(strings.ToLower(osInfo), "ubuntu") ||
		strings.Contains(strings.ToLower(osInfo), "debian") {
		// Ubuntu/Debian
		configFile = "/etc/default/qemu-guest-agent"
		configContent = `# Managed by eos - enable guest-exec for monitoring
DAEMON_ARGS=""
`
		restartCmd = "systemctl restart qemu-guest-agent"

	} else if strings.Contains(strings.ToLower(osInfo), "centos") ||
		strings.Contains(strings.ToLower(osInfo), "rhel") ||
		strings.Contains(strings.ToLower(osInfo), "rocky") ||
		strings.Contains(strings.ToLower(osInfo), "alma") {
		// CentOS/RHEL/Rocky/AlmaLinux
		configFile = "/etc/sysconfig/qemu-ga"
		configContent = `# Managed by eos - enable guest-exec for monitoring
BLACKLIST_RPC=
`
		restartCmd = "systemctl restart qemu-guest-agent"

	} else {
		return fmt.Errorf("unsupported OS: %s (manual configuration required)", osInfo)
	}

	logger.Info("Using config file",
		zap.String("path", configFile),
		zap.String("restart_cmd", restartCmd))

	// Step 5: Write config file using guest-file-write
	// This works even when guest-exec is disabled!
	logger.Info("Writing config file via guest-file-write")

	if err := writeGuestFile(domain, configFile, configContent); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	logger.Info("✓ Config file written successfully")

	// Step 6: Restart guest agent using guest-exec
	// This may fail if guest-exec is completely disabled, so we'll try and report
	logger.Info("Attempting to restart guest agent")

	if err := restartGuestAgent(domain, restartCmd); err != nil {
		logger.Warn("Failed to restart guest agent automatically",
			zap.Error(err))
		fmt.Println("⚠ Could not restart guest agent automatically")
		fmt.Println("  Please SSH into the VM and run:")
		fmt.Printf("    sudo %s\n", restartCmd)
		fmt.Println()
		fmt.Println("  Or reboot the VM:")
		fmt.Println("    virsh reboot " + vmName)
		return nil
	}

	// Wait for guest agent to come back online
	logger.Info("Waiting for guest agent to restart")
	time.Sleep(3 * time.Second)

	// Step 7: Verify guest-exec is now enabled
	logger.Info("Verifying guest-exec is enabled")
	afterStatus := testGuestExec(domain)

	logger.Info("Status after configuration",
		zap.String("before", beforeStatus),
		zap.String("after", afterStatus))

	if afterStatus == "ENABLED" {
		logger.Info("✓ guest-exec successfully enabled")
		fmt.Println()
		fmt.Println("✓ guest-exec successfully enabled")
		fmt.Println("  You can now use 'eos list kvm' to see full monitoring data")

		// Audit log successful enablement
		auditGuestExecChange(vmName, "enable", "manual", "success")

		return nil
	}

	// If still not working, provide manual instructions
	fmt.Println()
	fmt.Println("⚠ guest-exec status:", afterStatus)
	fmt.Println("  Config file has been written, but guest agent needs restart")
	fmt.Println()
	fmt.Println("  Please reboot the VM to apply changes:")
	fmt.Println("    virsh reboot " + vmName)
	fmt.Println()
	fmt.Println("  Or SSH into the VM and manually restart:")
	fmt.Printf("    sudo %s\n", restartCmd)

	// Audit log partial success (config written, needs restart)
	auditGuestExecChange(vmName, "enable", "manual", "pending_restart")

	return nil
}

// testGuestExec tests whether guest-exec is enabled
// Returns: "ENABLED", "DISABLED", or "ERROR"
func testGuestExec(domain *libvirt.Domain) string {
	// Try a harmless command: echo test
	cmd := `{"execute":"guest-exec","arguments":{"path":"/bin/echo","arg":["test"],"capture-output":true}}`
	_, err := domain.QemuAgentCommand(
		cmd,
		libvirt.DomainQemuAgentCommandTimeout(libvirt.DOMAIN_QEMU_AGENT_COMMAND_DEFAULT),
		0,
	)

	if err == nil {
		return "ENABLED"
	}

	if strings.Contains(err.Error(), "has been disabled") {
		return "DISABLED"
	}

	return "ERROR"
}

// writeGuestFile writes a file inside the guest using guest-file-open/write/close
// This works even when guest-exec is disabled
func writeGuestFile(domain *libvirt.Domain, path, content string) error {
	// Step 1: Open file for writing
	openCmd := fmt.Sprintf(`{"execute":"guest-file-open","arguments":{"path":"%s","mode":"w"}}`, path)
	result, err := domain.QemuAgentCommand(
		openCmd,
		libvirt.DomainQemuAgentCommandTimeout(libvirt.DOMAIN_QEMU_AGENT_COMMAND_DEFAULT),
		0,
	)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}

	// Parse file handle
	var openResponse struct {
		Return int `json:"return"`
	}
	if err := json.Unmarshal([]byte(result), &openResponse); err != nil {
		return fmt.Errorf("failed to parse open response: %w", err)
	}

	handle := openResponse.Return

	// Step 2: Write content (base64 encoded)
	encodedContent := base64.StdEncoding.EncodeToString([]byte(content))
	writeCmd := fmt.Sprintf(`{"execute":"guest-file-write","arguments":{"handle":%d,"buf-b64":"%s"}}`,
		handle, encodedContent)

	_, err = domain.QemuAgentCommand(
		writeCmd,
		libvirt.DomainQemuAgentCommandTimeout(libvirt.DOMAIN_QEMU_AGENT_COMMAND_DEFAULT),
		0,
	)
	if err != nil {
		// Try to close handle before returning error
		closeCmd := fmt.Sprintf(`{"execute":"guest-file-close","arguments":{"handle":%d}}`, handle)
		_, _ = domain.QemuAgentCommand(closeCmd,
			libvirt.DomainQemuAgentCommandTimeout(libvirt.DOMAIN_QEMU_AGENT_COMMAND_DEFAULT), 0)
		return fmt.Errorf("failed to write file: %w", err)
	}

	// Step 3: Close file
	closeCmd := fmt.Sprintf(`{"execute":"guest-file-close","arguments":{"handle":%d}}`, handle)
	if _, err := domain.QemuAgentCommand(
		closeCmd,
		libvirt.DomainQemuAgentCommandTimeout(libvirt.DOMAIN_QEMU_AGENT_COMMAND_DEFAULT),
		0,
	); err != nil {
		return fmt.Errorf("failed to close file: %w", err)
	}

	return nil
}

// restartGuestAgent attempts to restart the guest agent service
func restartGuestAgent(domain *libvirt.Domain, restartCmd string) error {
	// Try using guest-exec (may fail if disabled)
	cmd := fmt.Sprintf(`{"execute":"guest-exec","arguments":{"path":"/bin/sh","arg":["-c","%s"]}}`, restartCmd)
	result, err := domain.QemuAgentCommand(
		cmd,
		libvirt.DomainQemuAgentCommandTimeout(libvirt.DOMAIN_QEMU_AGENT_COMMAND_DEFAULT),
		0,
	)

	if err != nil {
		return fmt.Errorf("guest-exec failed: %w", err)
	}

	// Parse response to get PID
	var execResponse struct {
		Return struct {
			PID int `json:"pid"`
		} `json:"return"`
	}

	if err := json.Unmarshal([]byte(result), &execResponse); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Command was submitted successfully
	// Note: We can't wait for it to complete because restarting the agent
	// will disconnect us
	return nil
}

// EnableGuestExecBulk enables guest-exec for all VMs with DISABLED status
func EnableGuestExecBulk(rc *eos_io.RuntimeContext, skipConfirm bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Finding VMs with DISABLED guest-exec status")

	// Get all VMs
	vms, err := ListVMs(rc)
	if err != nil {
		return fmt.Errorf("failed to list VMs: %w", err)
	}

	// Find VMs with DISABLED status
	var disabledVMs []string
	for _, vm := range vms {
		if vm.ConsulAgent == "DISABLED" || vm.UpdatesNeeded == "DISABLED" {
			// Only include running VMs (can't enable guest-exec on stopped VMs)
			if vm.State == "running" {
				disabledVMs = append(disabledVMs, vm.Name)
			}
		}
	}

	if len(disabledVMs) == 0 {
		fmt.Println("✓ No VMs found with DISABLED guest-exec status")
		return nil
	}

	// Show VMs that will be updated
	fmt.Printf("Found %d VM(s) with DISABLED guest-exec:\n", len(disabledVMs))
	for _, vmName := range disabledVMs {
		fmt.Printf("  - %s\n", vmName)
	}
	fmt.Println()

	// Confirm unless --yes was provided
	if !skipConfirm {
		fmt.Print("Enable guest-exec for all these VMs? (yes/no): ")
		var response string
		_, _ = fmt.Scanln(&response)
		if response != "yes" && response != "y" {
			fmt.Println("Cancelled")
			return nil
		}
	}

	// Track results
	type result struct {
		vm     string
		status string
		err    error
	}

	results := make([]result, 0, len(disabledVMs))

	// Process each VM
	fmt.Println()
	for i, vmName := range disabledVMs {
		fmt.Printf("[%d/%d] Enabling guest-exec for %s...\n", i+1, len(disabledVMs), vmName)

		err := EnableGuestExec(rc, vmName)
		if err != nil {
			fmt.Printf("  ✗ Failed: %v\n", err)
			results = append(results, result{vm: vmName, status: "FAILED", err: err})
			logger.Error("Failed to enable guest-exec",
				zap.String("vm", vmName),
				zap.Error(err))
		} else {
			fmt.Printf("  ✓ Success\n")
			results = append(results, result{vm: vmName, status: "SUCCESS", err: nil})
			logger.Info("Successfully enabled guest-exec",
				zap.String("vm", vmName))
		}
		fmt.Println()
	}

	// Show summary
	successCount := 0
	failedCount := 0
	for _, r := range results {
		if r.status == "SUCCESS" {
			successCount++
		} else {
			failedCount++
		}
	}

	fmt.Println("═══════════════════════════════════════")
	fmt.Printf("SUMMARY: %d VMs processed\n", len(results))
	fmt.Printf("  ✓ Success: %d\n", successCount)
	if failedCount > 0 {
		fmt.Printf("  ✗ Failed:  %d\n", failedCount)
		fmt.Println()
		fmt.Println("Failed VMs:")
		for _, r := range results {
			if r.status == "FAILED" {
				fmt.Printf("  - %s: %v\n", r.vm, r.err)
			}
		}
	}
	fmt.Println("═══════════════════════════════════════")

	if failedCount > 0 {
		return fmt.Errorf("%d out of %d VMs failed", failedCount, len(results))
	}

	return nil
}

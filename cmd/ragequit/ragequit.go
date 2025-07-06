package ragequit

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RagequitCmd represents the ragequit command
var RagequitCmd = &cobra.Command{
	Use:   "ragequit",
	Short: "Emergency system diagnostic and recovery tool",
	Long: `Emergency system diagnostic and recovery tool for when things go completely wrong.

Ragequit performs comprehensive system diagnostics, captures critical state information,
and can optionally reboot the system to recover from stuck processes or system loops.

Features:
- Environment detection (containers, cloud, bare metal)
- Universal resource exhaustion checks
- Database and queue system diagnostics
- Security incident response data collection
- Post-reboot recovery automation
- Configurable notification systems`,
	RunE: eos.Wrap(runRagequit),
}

var (
	reason   string
	noReboot bool
	force    bool
	actions  string
)

func init() {
	RagequitCmd.Flags().StringVar(&reason, "reason", "", "Document why ragequit was triggered")
	RagequitCmd.Flags().BoolVar(&noReboot, "no-reboot", false, "Collect diagnostics but don't reboot")
	RagequitCmd.Flags().BoolVar(&force, "force", false, "Skip confirmation prompt")
	RagequitCmd.Flags().StringVar(&actions, "actions", "all", "Actions to perform: all, minimal, diagnostics-only, custom")
}

func runRagequit(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Warn("🚨 EMERGENCY: Ragequit initiated",
		zap.String("user", os.Getenv("USER")),
		zap.String("hostname", getHostname()),
		zap.String("reason", reason),
		zap.Bool("no_reboot", noReboot),
		zap.String("actions", actions))

	// Confirmation prompt unless forced
	if !force {
		if !confirmRagequit(rc) {
			logger.Info("Ragequit cancelled by user")
			return nil
		}
	}

	// Create timestamp file for tracking
	createTimestampFile(rc, reason)

	// Start diagnostic collection
	logger.Info("Starting emergency diagnostic collection",
		zap.String("phase", "diagnostics"),
		zap.String("output_dir", getHomeDir()))

	var wg sync.WaitGroup

	// Run all diagnostic functions in parallel for speed
	diagnosticFuncs := []func(*eos_io.RuntimeContext){
		detectEnvironment,
		checkResources,
		checkQueues,
		checkDatabases,
		securitySnapshot,
		containerDiagnostics,
		performanceSnapshot,
		systemctlDiagnostics,
		networkDiagnostics,
		customHooks,
	}

	for _, fn := range diagnosticFuncs {
		wg.Add(1)
		go func(diagFunc func(*eos_io.RuntimeContext)) {
			defer wg.Done()
			diagFunc(rc)
		}(fn)
	}

	// Wait for all diagnostics to complete (with timeout)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Info("All diagnostics completed successfully")
	case <-time.After(30 * time.Second):
		logger.Warn("Diagnostic collection timeout, proceeding anyway",
			zap.Duration("timeout", 30*time.Second))
	}

	// Generate recovery plan
	generateRecoveryPlan(rc)

	// Setup post-reboot automation
	createPostRebootRecovery(rc)

	// Send notifications
	notifyRagequit(rc)

	// Final preparations before reboot
	flushDataSafety(rc)

	if !noReboot {
		logger.Error("🔥 INITIATING EMERGENCY REBOOT",
			zap.String("countdown", "5 seconds"),
			zap.String("reason", reason))

		// Final countdown
		for i := 5; i > 0; i-- {
			logger.Warn("Rebooting in", zap.Int("seconds", i))
			time.Sleep(1 * time.Second)
		}

		// Execute reboot
		return executeReboot(rc)
	} else {
		logger.Info("Diagnostic collection complete - no reboot requested",
			zap.String("investigation_file", filepath.Join(getHomeDir(), "investigate-ragequit.md")))
		return nil
	}
}

func confirmRagequit(rc *eos_io.RuntimeContext) bool {
	logger := otelzap.Ctx(rc.Ctx)

	fmt.Print("🚨 EMERGENCY RAGEQUIT 🚨\n")
	fmt.Print("This will:\n")
	fmt.Print("1. Collect comprehensive system diagnostics\n")
	fmt.Print("2. Create emergency backup files\n")
	if !noReboot {
		fmt.Print("3. REBOOT THE SYSTEM IMMEDIATELY\n")
	}
	fmt.Print("\nAre you sure you want to continue? (yes/no): ")

	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		logger.Error("Failed to read user input", zap.Error(err))
		return false
	}

	response = strings.TrimSpace(strings.ToLower(response))
	return response == "yes" || response == "y"
}

func createTimestampFile(rc *eos_io.RuntimeContext, reason string) {
	logger := otelzap.Ctx(rc.Ctx)
	homeDir := getHomeDir()
	timestampFile := filepath.Join(homeDir, "ragequit-timestamp.txt")

	content := fmt.Sprintf("Ragequit executed at: %s\nTriggered by: %s\nReason: %s\nHostname: %s\n",
		time.Now().Format(time.RFC3339),
		os.Getenv("USER"),
		reason,
		getHostname())

	if err := os.WriteFile(timestampFile, []byte(content), 0644); err != nil {
		logger.Error("Failed to create timestamp file", zap.Error(err))
	} else {
		logger.Info("Created ragequit timestamp file", zap.String("file", timestampFile))
	}
}

func detectEnvironment(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)
	homeDir := getHomeDir()
	outputFile := filepath.Join(homeDir, "ragequit-environment.txt")

	var output strings.Builder
	output.WriteString("=== Environment Detection ===\n")

	// Container detection
	if fileExists("/.dockerenv") {
		output.WriteString("Environment: Docker Container\n")
		if dockerInfo := runCommandWithTimeout("docker", []string{"info"}, 5*time.Second); dockerInfo != "" {
			output.WriteString(dockerInfo)
		}
	} else if fileExists("/run/.containerenv") {
		output.WriteString("Environment: Podman Container\n")
	} else if containsString("/proc/1/cgroup", "kubernetes") {
		output.WriteString("Environment: Kubernetes Pod\n")
		if k8sInfo := runCommandWithTimeout("kubectl", []string{"get", "pods", "--all-namespaces"}, 5*time.Second); k8sInfo != "" {
			output.WriteString(k8sInfo)
		}
	} else {
		output.WriteString("Environment: Bare Metal/VM\n")
	}

	// Cloud provider detection
	if commandExists("ec2-metadata") {
		output.WriteString("Cloud: AWS EC2\n")
		if awsInfo := runCommandWithTimeout("ec2-metadata", []string{"--all"}, 5*time.Second); awsInfo != "" {
			output.WriteString(awsInfo)
		}
	} else if containsString("/sys/class/dmi/id/product_name", "Google") {
		output.WriteString("Cloud: Google Cloud\n")
	} else if containsString("/sys/class/dmi/id/sys_vendor", "Microsoft Corporation") {
		output.WriteString("Cloud: Azure\n")
	}

	// Init system detection
	if dirExists("/run/systemd/system") {
		output.WriteString("Init: systemd\n")
	} else if commandExists("initctl") {
		output.WriteString("Init: upstart\n")
	} else if fileExists("/etc/init.d/rc") {
		output.WriteString("Init: sysvinit\n")
	}

	if err := os.WriteFile(outputFile, []byte(output.String()), 0644); err != nil {
		logger.Error("Failed to write environment detection", zap.Error(err))
	} else {
		logger.Info("Environment detection completed", zap.String("file", outputFile))
	}
}

func checkResources(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)
	homeDir := getHomeDir()
	outputFile := filepath.Join(homeDir, "ragequit-resources.txt")

	var output strings.Builder
	output.WriteString("=== Resource Exhaustion Check ===\n")

	// Disk space
	if diskInfo := runCommandWithTimeout("df", []string{"-h"}, 5*time.Second); diskInfo != "" {
		output.WriteString("\n--- Disk Space ---\n")
		output.WriteString(diskInfo)
	}

	if inodeInfo := runCommandWithTimeout("df", []string{"-i"}, 5*time.Second); inodeInfo != "" {
		output.WriteString("\n--- Inode Usage ---\n")
		output.WriteString(inodeInfo)
	}

	// Memory details
	if memInfo := readFile("/proc/meminfo"); memInfo != "" {
		output.WriteString("\n--- Memory Information ---\n")
		lines := strings.Split(memInfo, "\n")
		for _, line := range lines {
			if strings.Contains(line, "Dirty") || strings.Contains(line, "Writeback") ||
				strings.Contains(line, "AnonPages") || strings.Contains(line, "Slab") {
				output.WriteString(line + "\n")
			}
		}
	}

	// Top CPU consumers
	if topInfo := runCommandWithTimeout("ps", []string{"aux", "--sort=-%cpu"}, 5*time.Second); topInfo != "" {
		output.WriteString("\n--- Top CPU Consumers ---\n")
		lines := strings.Split(topInfo, "\n")
		for i, line := range lines {
			if i < 21 { // Header + top 20
				output.WriteString(line + "\n")
			}
		}
	}

	// Zombie processes
	if zombies := runCommandWithTimeout("ps", []string{"aux"}, 5*time.Second); zombies != "" {
		output.WriteString("\n--- Zombie Processes ---\n")
		lines := strings.Split(zombies, "\n")
		for _, line := range lines {
			if strings.Contains(line, " Z ") {
				output.WriteString(line + "\n")
			}
		}
	}

	if err := os.WriteFile(outputFile, []byte(output.String()), 0644); err != nil {
		logger.Error("Failed to write resource check", zap.Error(err))
	} else {
		logger.Info("Resource check completed", zap.String("file", outputFile))
	}
}

func checkQueues(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)
	homeDir := getHomeDir()
	outputFile := filepath.Join(homeDir, "ragequit-queues.txt")

	var output strings.Builder
	output.WriteString("=== Queue Systems Status ===\n")

	// Redis
	if commandExists("redis-cli") {
		output.WriteString("\n--- Redis ---\n")
		if redisInfo := runCommandWithTimeout("redis-cli", []string{"INFO", "stats"}, 3*time.Second); redisInfo != "" {
			output.WriteString(redisInfo)
		}
		if clientList := runCommandWithTimeout("redis-cli", []string{"CLIENT", "LIST"}, 3*time.Second); clientList != "" {
			output.WriteString("\nClient List:\n" + clientList)
		}
	}

	// RabbitMQ
	if commandExists("rabbitmqctl") {
		output.WriteString("\n--- RabbitMQ ---\n")
		if queueList := runCommandWithTimeout("rabbitmqctl", []string{"list_queues"}, 5*time.Second); queueList != "" {
			output.WriteString(queueList)
		}
	}

	// Generic TCP queue detection
	if tcpStats := runCommandWithTimeout("ss", []string{"-ant"}, 5*time.Second); tcpStats != "" {
		output.WriteString("\n--- TCP Connection States ---\n")
		output.WriteString(tcpStats)
	}

	if err := os.WriteFile(outputFile, []byte(output.String()), 0644); err != nil {
		logger.Error("Failed to write queue check", zap.Error(err))
	} else {
		logger.Info("Queue systems check completed", zap.String("file", outputFile))
	}
}

func checkDatabases(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)
	homeDir := getHomeDir()
	outputFile := filepath.Join(homeDir, "ragequit-databases.txt")

	var output strings.Builder
	output.WriteString("=== Database Status ===\n")

	// PostgreSQL
	if commandExists("psql") {
		output.WriteString("\n--- PostgreSQL ---\n")
		if pgActivity := runCommandWithTimeout("sudo", []string{"-u", "postgres", "psql", "-c", "SELECT state, count(*) FROM pg_stat_activity GROUP BY state;"}, 5*time.Second); pgActivity != "" {
			output.WriteString(pgActivity)
		}
	}

	// MySQL/MariaDB
	if commandExists("mysql") {
		output.WriteString("\n--- MySQL/MariaDB ---\n")
		if mysqlProc := runCommandWithTimeout("mysql", []string{"-e", "SHOW PROCESSLIST;"}, 5*time.Second); mysqlProc != "" {
			output.WriteString(mysqlProc)
		}
	}

	if err := os.WriteFile(outputFile, []byte(output.String()), 0644); err != nil {
		logger.Error("Failed to write database check", zap.Error(err))
	} else {
		logger.Info("Database check completed", zap.String("file", outputFile))
	}
}

func securitySnapshot(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)
	homeDir := getHomeDir()
	outputFile := filepath.Join(homeDir, "ragequit-security.txt")

	var output strings.Builder
	output.WriteString("=== Security Snapshot ===\n")

	// Recent logins
	if lastInfo := runCommandWithTimeout("last", []string{"-20"}, 5*time.Second); lastInfo != "" {
		output.WriteString("\n--- Recent Logins ---\n")
		output.WriteString(lastInfo)
	}

	// Currently logged in users
	if whoInfo := runCommandWithTimeout("who", []string{}, 3*time.Second); whoInfo != "" {
		output.WriteString("\n--- Currently Logged In ---\n")
		output.WriteString(whoInfo)
	}

	// Network connections
	if netConnections := runCommandWithTimeout("ss", []string{"-plant"}, 5*time.Second); netConnections != "" {
		output.WriteString("\n--- Network Connections ---\n")
		output.WriteString(netConnections)
	}

	// Running processes
	if processes := runCommandWithTimeout("ps", []string{"auxww"}, 5*time.Second); processes != "" {
		output.WriteString("\n--- All Processes ---\n")
		output.WriteString(processes)
	}

	if err := os.WriteFile(outputFile, []byte(output.String()), 0644); err != nil {
		logger.Error("Failed to write security snapshot", zap.Error(err))
	} else {
		logger.Info("Security snapshot completed", zap.String("file", outputFile))
	}
}

func containerDiagnostics(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)
	homeDir := getHomeDir()

	if commandExists("docker") {
		outputFile := filepath.Join(homeDir, "ragequit-docker.txt")
		var output strings.Builder
		output.WriteString("=== Docker Diagnostics ===\n")

		if dockerPs := runCommandWithTimeout("docker", []string{"ps", "-a"}, 10*time.Second); dockerPs != "" {
			output.WriteString("\n--- Docker Containers ---\n")
			output.WriteString(dockerPs)
		}

		if dockerStats := runCommandWithTimeout("docker", []string{"stats", "--no-stream"}, 10*time.Second); dockerStats != "" {
			output.WriteString("\n--- Docker Stats ---\n")
			output.WriteString(dockerStats)
		}

		if err := os.WriteFile(outputFile, []byte(output.String()), 0644); err != nil {
			logger.Error("Failed to write Docker diagnostics", zap.Error(err))
		} else {
			logger.Info("Docker diagnostics completed", zap.String("file", outputFile))
		}
	}

	if commandExists("kubectl") {
		outputFile := filepath.Join(homeDir, "ragequit-k8s.txt")
		var output strings.Builder
		output.WriteString("=== Kubernetes Diagnostics ===\n")

		if k8sAll := runCommandWithTimeout("kubectl", []string{"get", "all", "--all-namespaces"}, 10*time.Second); k8sAll != "" {
			output.WriteString("\n--- Kubernetes Resources ---\n")
			output.WriteString(k8sAll)
		}

		if k8sEvents := runCommandWithTimeout("kubectl", []string{"get", "events", "--all-namespaces", "--sort-by=.lastTimestamp"}, 10*time.Second); k8sEvents != "" {
			output.WriteString("\n--- Recent Events ---\n")
			lines := strings.Split(k8sEvents, "\n")
			start := len(lines) - 100
			if start < 0 {
				start = 0
			}
			for i := start; i < len(lines); i++ {
				output.WriteString(lines[i] + "\n")
			}
		}

		if err := os.WriteFile(outputFile, []byte(output.String()), 0644); err != nil {
			logger.Error("Failed to write Kubernetes diagnostics", zap.Error(err))
		} else {
			logger.Info("Kubernetes diagnostics completed", zap.String("file", outputFile))
		}
	}
}

func performanceSnapshot(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)
	homeDir := getHomeDir()
	outputFile := filepath.Join(homeDir, "ragequit-performance.txt")

	var output strings.Builder
	output.WriteString("=== Performance Snapshot ===\n")

	// CPU info
	if cpuInfo := readFile("/proc/cpuinfo"); cpuInfo != "" {
		output.WriteString("\n--- CPU Information ---\n")
		lines := strings.Split(cpuInfo, "\n")
		for _, line := range lines {
			if strings.Contains(strings.ToLower(line), "mhz") {
				output.WriteString(line + "\n")
			}
		}
	}

	// Memory stats
	if vmStat := runCommandWithTimeout("vmstat", []string{"1", "3"}, 10*time.Second); vmStat != "" {
		output.WriteString("\n--- Memory/CPU Stats ---\n")
		output.WriteString(vmStat)
	}

	// I/O stats
	if ioStat := runCommandWithTimeout("iostat", []string{"-x", "1", "2"}, 5*time.Second); ioStat != "" {
		output.WriteString("\n--- I/O Stats ---\n")
		output.WriteString(ioStat)
	}

	// Network stats
	if netStat := runCommandWithTimeout("netstat", []string{"-s"}, 5*time.Second); netStat != "" {
		output.WriteString("\n--- Network Stats ---\n")
		output.WriteString(netStat)
	}

	if err := os.WriteFile(outputFile, []byte(output.String()), 0644); err != nil {
		logger.Error("Failed to write performance snapshot", zap.Error(err))
	} else {
		logger.Info("Performance snapshot completed", zap.String("file", outputFile))
	}
}

func systemctlDiagnostics(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)
	homeDir := getHomeDir()

	if !commandExists("systemctl") {
		return
	}

	// Failed units
	if failedUnits := runCommandWithTimeout("systemctl", []string{"list-units", "--failed", "--no-pager"}, 5*time.Second); failedUnits != "" {
		outputFile := filepath.Join(homeDir, "failed-units.backup")
		if err := os.WriteFile(outputFile, []byte(failedUnits), 0644); err != nil {
			logger.Error("Failed to write failed units", zap.Error(err))
		} else {
			logger.Info("Failed units captured", zap.String("file", outputFile))
		}
	}

	// Pending jobs
	if pendingJobs := runCommandWithTimeout("systemctl", []string{"list-jobs", "--no-pager"}, 5*time.Second); pendingJobs != "" {
		outputFile := filepath.Join(homeDir, "pending-jobs.backup")
		if err := os.WriteFile(outputFile, []byte(pendingJobs), 0644); err != nil {
			logger.Error("Failed to write pending jobs", zap.Error(err))
		} else {
			logger.Info("Pending jobs captured", zap.String("file", outputFile))
		}
	}

	// Recent journal errors
	if journalErrors := runCommandWithTimeout("journalctl", []string{"-p", "err", "-n", "100", "--no-pager"}, 10*time.Second); journalErrors != "" {
		outputFile := filepath.Join(homeDir, "journal-errors.backup")
		if err := os.WriteFile(outputFile, []byte(journalErrors), 0644); err != nil {
			logger.Error("Failed to write journal errors", zap.Error(err))
		} else {
			logger.Info("Journal errors captured", zap.String("file", outputFile))
		}
	}
}

func networkDiagnostics(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)
	homeDir := getHomeDir()

	// Network listeners
	if netListeners := runCommandWithTimeout("ss", []string{"-tlnp"}, 5*time.Second); netListeners != "" {
		outputFile := filepath.Join(homeDir, "network-listeners.backup")
		if err := os.WriteFile(outputFile, []byte(netListeners), 0644); err != nil {
			logger.Error("Failed to write network listeners", zap.Error(err))
		} else {
			logger.Info("Network listeners captured", zap.String("file", outputFile))
		}
	}

	// Network interfaces
	if netInterfaces := runCommandWithTimeout("ip", []string{"addr"}, 5*time.Second); netInterfaces != "" {
		outputFile := filepath.Join(homeDir, "network-interfaces.backup")
		if err := os.WriteFile(outputFile, []byte(netInterfaces), 0644); err != nil {
			logger.Error("Failed to write network interfaces", zap.Error(err))
		} else {
			logger.Info("Network interfaces captured", zap.String("file", outputFile))
		}
	}
}

func customHooks(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)
	hooksDir := "/etc/eos/ragequit-hooks"

	if !dirExists(hooksDir) {
		return
	}

	homeDir := getHomeDir()
	outputFile := filepath.Join(homeDir, "ragequit-custom.txt")

	files, err := os.ReadDir(hooksDir)
	if err != nil {
		logger.Error("Failed to read hooks directory", zap.Error(err))
		return
	}

	var output strings.Builder
	output.WriteString("=== Custom Hooks Output ===\n")

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		hookPath := filepath.Join(hooksDir, file.Name())
		if isExecutable(hookPath) {
			output.WriteString(fmt.Sprintf("\n--- Hook: %s ---\n", file.Name()))
			if hookOutput := runCommandWithTimeout(hookPath, []string{}, 30*time.Second); hookOutput != "" {
				output.WriteString(hookOutput)
			}
		}
	}

	if err := os.WriteFile(outputFile, []byte(output.String()), 0644); err != nil {
		logger.Error("Failed to write custom hooks output", zap.Error(err))
	} else {
		logger.Info("Custom hooks executed", zap.String("file", outputFile))
	}
}

func generateRecoveryPlan(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)
	homeDir := getHomeDir()
	outputFile := filepath.Join(homeDir, "investigate-ragequit.md")

	var plan strings.Builder
	plan.WriteString("# Ragequit Investigation Checklist\n\n")
	plan.WriteString(fmt.Sprintf("Generated at: %s\n", time.Now().Format(time.RFC3339)))
	plan.WriteString(fmt.Sprintf("Triggered by: %s\n", os.Getenv("USER")))
	plan.WriteString(fmt.Sprintf("Reason: %s\n\n", reason))

	plan.WriteString("## Investigation Steps\n\n")
	plan.WriteString("1. **Check archived logs** in ragequit-*.txt files\n")
	plan.WriteString("2. **Review service configurations** for Type=notify with notification issues\n")
	plan.WriteString("3. **Look for looping processes** in journal-errors.backup\n")
	plan.WriteString("4. **Identify resource exhaustion** in ragequit-resources.txt\n")
	plan.WriteString("5. **Check security incidents** in ragequit-security.txt\n\n")

	plan.WriteString("## Recovery Commands\n\n")
	plan.WriteString("```bash\n")
	plan.WriteString("# Monitor system health\n")
	plan.WriteString("watch -n 1 'ps -p 1 -o %cpu'\n\n")
	plan.WriteString("# Check systemd status\n")
	plan.WriteString("systemctl is-system-running\n\n")
	plan.WriteString("# Mask problematic services (if identified)\n")
	plan.WriteString("sudo systemctl mask SERVICE_NAME\n\n")
	plan.WriteString("# Unmask and test services one by one\n")
	plan.WriteString("sudo systemctl unmask SERVICE_NAME\n")
	plan.WriteString("sudo systemctl start SERVICE_NAME\n")
	plan.WriteString("```\n\n")

	plan.WriteString("## Files Generated\n\n")

	// List all ragequit files
	files, err := filepath.Glob(filepath.Join(homeDir, "ragequit-*.txt"))
	if err == nil {
		sort.Strings(files)
		for _, file := range files {
			plan.WriteString(fmt.Sprintf("- `%s`\n", filepath.Base(file)))
		}
	}

	backupFiles, err := filepath.Glob(filepath.Join(homeDir, "*.backup"))
	if err == nil {
		sort.Strings(backupFiles)
		for _, file := range backupFiles {
			plan.WriteString(fmt.Sprintf("- `%s`\n", filepath.Base(file)))
		}
	}

	if err := os.WriteFile(outputFile, []byte(plan.String()), 0644); err != nil {
		logger.Error("Failed to write recovery plan", zap.Error(err))
	} else {
		logger.Info("Recovery plan generated", zap.String("file", outputFile))
	}
}

func createPostRebootRecovery(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)
	homeDir := getHomeDir()
	scriptFile := filepath.Join(homeDir, "post-ragequit-recovery.sh")

	script := `#!/bin/bash
# Auto-run after ragequit reboot

echo "=== Post-Ragequit Recovery Starting ==="
date

# Check if we just came from a ragequit
if [ -f ~/ragequit-timestamp.txt ]; then
    echo "System rebooted after ragequit event:"
    cat ~/ragequit-timestamp.txt
    
    # Archive the diagnostic files
    ARCHIVE_DIR="$HOME/ragequit-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$ARCHIVE_DIR"
    mv ~/ragequit-*.txt ~/*.backup "$ARCHIVE_DIR/" 2>/dev/null || true
    
    # Check systemd health
    echo -e "\nSystemd health check:"
    systemctl is-system-running
    ps -p 1 -o %cpu,etime
    
    echo -e "\nRecovery complete. See ~/investigate-ragequit.md for next steps."
    echo "Diagnostic files archived in: $ARCHIVE_DIR"
else
    echo "Normal boot detected (no ragequit timestamp found)"
fi
`

	if err := os.WriteFile(scriptFile, []byte(script), 0755); err != nil {
		logger.Error("Failed to create post-reboot recovery script", zap.Error(err))
	} else {
		logger.Info("Post-reboot recovery script created", zap.String("file", scriptFile))
	}

	// Add to profile for auto-execution
	profileFile := filepath.Join(homeDir, ".bashrc")
	profileEntry := "[ -f ~/ragequit-timestamp.txt ] && ~/post-ragequit-recovery.sh\n"

	// Check if entry already exists
	if content := readFile(profileFile); !strings.Contains(content, "post-ragequit-recovery.sh") {
		file, err := os.OpenFile(profileFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			logger.Error("Failed to update .bashrc", zap.Error(err))
		} else {
			defer func() {
				if closeErr := file.Close(); closeErr != nil {
					logger.Error("Failed to close .bashrc file", zap.Error(closeErr))
				}
			}()
			if _, err := file.WriteString(profileEntry); err != nil {
				logger.Error("Failed to write to .bashrc", zap.Error(err))
			} else {
				logger.Info("Added post-reboot hook to .bashrc")
			}
		}
	}
}

func notifyRagequit(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)

	// Webhook notification
	if webhookURL := os.Getenv("Eos_EMERGENCY_WEBHOOK"); webhookURL != "" {
		message := fmt.Sprintf("🚨 EMERGENCY: Ragequit initiated on %s by %s", getHostname(), os.Getenv("USER"))
		if curlOutput := runCommandWithTimeout("curl", []string{
			"-X", "POST", webhookURL,
			"-H", "Content-Type: application/json",
			"-d", fmt.Sprintf(`{"text":"%s"}`, message),
		}, 5*time.Second); curlOutput != "" {
			logger.Info("Emergency webhook notification sent", zap.String("webhook", webhookURL))
		}
	}

	// Email notification
	if email := os.Getenv("RAGEQUIT_EMAIL"); email != "" && commandExists("mail") {
		subject := fmt.Sprintf("EMERGENCY: Ragequit %s", getHostname())
		message := fmt.Sprintf("Ragequit initiated on %s by %s at %s\nReason: %s",
			getHostname(), os.Getenv("USER"), time.Now().Format(time.RFC3339), reason)

		// Send email via stdin
		cmd := exec.Command("mail", "-s", subject, email)
		cmd.Stdin = strings.NewReader(message)
		if err := cmd.Run(); err == nil {
			logger.Info("Emergency email notification sent", zap.String("email", email))
		}
	}

	// Create emergency flag file
	flagFile := "/var/run/ragequit-in-progress"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	if err := os.WriteFile(flagFile, []byte(timestamp), 0644); err != nil {
		logger.Warn("Failed to create emergency flag file", zap.Error(err))
	} else {
		logger.Info("Emergency flag file created", zap.String("file", flagFile))
	}
}

func flushDataSafety(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting data safety procedures")

	// Sync filesystem
	if syncOutput := runCommandWithTimeout("sync", []string{}, 10*time.Second); syncOutput != "" {
		logger.Info("Filesystem sync completed")
	}

	// PostgreSQL checkpoint
	if commandExists("psql") {
		if pgCheckpoint := runCommandWithTimeout("sudo", []string{"-u", "postgres", "psql", "-c", "CHECKPOINT;"}, 10*time.Second); pgCheckpoint != "" {
			logger.Info("PostgreSQL checkpoint completed")
		}
	}

	// Redis background save
	if commandExists("redis-cli") {
		if redisSave := runCommandWithTimeout("redis-cli", []string{"BGSAVE"}, 5*time.Second); redisSave != "" {
			logger.Info("Redis background save initiated")
		}
	}
}

func executeReboot(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Error("🔥 EXECUTING EMERGENCY REBOOT NOW")

	cmd := exec.Command("sudo", "reboot")
	if err := cmd.Start(); err != nil {
		logger.Error("Failed to execute reboot command", zap.Error(err))
		return err
	}

	// Don't wait for reboot to complete
	return nil
}

// Utility functions

func getHostname() string {
	if hostname, err := os.Hostname(); err == nil {
		return hostname
	}
	return "unknown"
}

func getHomeDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return home
	}
	return "/tmp"
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func commandExists(command string) bool {
	_, err := exec.LookPath(command)
	return err == nil
}

func isExecutable(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode()&0111 != 0
}

func containsString(filePath, searchString string) bool {
	content := readFile(filePath)
	return strings.Contains(content, searchString)
}

func readFile(path string) string {
	content, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(content)
}

func runCommandWithTimeout(command string, args []string, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, command, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}

	return string(output)
}

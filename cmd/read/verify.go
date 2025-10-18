package read

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify infrastructure state using OSQuery",
	Long: `Use OSQuery to perform out-of-band verification of infrastructure state.
This provides an independent check of what's actually running on the system.`,
	RunE: eos_cli.Wrap(runVerify),
}

func init() {
	ReadCmd.AddCommand(verifyCmd)

	verifyCmd.Flags().Bool("clean", false, "Verify system is in clean state (nothing installed)")
	verifyCmd.Flags().Bool("json", false, "Output raw OSQuery JSON results")
}

func runVerify(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	checkClean := cmd.Flag("clean").Value.String() == "true"
	jsonOutput := cmd.Flag("json").Value.String() == "true"

	logger.Info("Running OSQuery verification",
		zap.Bool("check_clean", checkClean),
		zap.Bool("json_output", jsonOutput))

	cli := eos_cli.New(rc)

	// Check if OSQuery is available
	if _, err := cli.Which("osqueryi"); err != nil {
		return fmt.Errorf("OSQuery not installed. Install with: eos create bootstrap osquery")
	}

	if checkClean {
		return verifyCleanState(rc, cli, jsonOutput)
	}

	// Standard verification
	fmt.Println("OSQuery Infrastructure Verification")
	fmt.Println("==================================")
	fmt.Println()

	// 1. Check running processes
	fmt.Println("Running Processes:")
	fmt.Println("-----------------")

	processQuery := `SELECT name, path, cmdline, pid, state 
FROM processes 
WHERE name IN ('vault', 'nomad', 'consul', 'docker', 'osqueryd', 'clusterfuzz')
ORDER BY name;`

	if output, err := cli.ExecString("osqueryi", "--line", processQuery); err == nil {
		fmt.Println(output)
	} else {
		logger.Warn("Failed to query processes", zap.Error(err))
	}

	// 2. Check listening ports
	fmt.Println("\nListening Ports:")
	fmt.Println("---------------")

	portQuery := fmt.Sprintf(`SELECT DISTINCT
  process.name as process_name,
  listening.port,
  listening.protocol,
  listening.address
FROM listening_ports AS listening
JOIN processes AS process USING (pid)
WHERE listening.port != 0
  AND process.name != ''
  AND listening.port IN (4505, 4506, %d, %d, 4646, 4647, 4648, 8300, 8301, 8302, 8500, 8600)
ORDER BY listening.port;`, shared.PortVault, shared.PortVault+1)

	if output, err := cli.ExecString("osqueryi", "--line", portQuery); err == nil {
		fmt.Println(output)
	} else {
		logger.Warn("Failed to query ports", zap.Error(err))
	}

	// 3. Check installed packages
	fmt.Println("\nInstalled Packages:")
	fmt.Println("------------------")

	packageQuery := `SELECT name, version 
FROM deb_packages 
WHERE name IN ('vault', 'nomad', 'consul', 'docker-ce', 'osquery')
ORDER BY name;`

	if output, err := cli.ExecString("osqueryi", "--line", packageQuery); err == nil {
		fmt.Println(output)
	} else {
		logger.Warn("Failed to query packages", zap.Error(err))
	}

	// 4. Check systemd services
	fmt.Println("\nSystemd Services:")
	fmt.Println("----------------")

	serviceQuery := `SELECT name, status, pid 
FROM systemd_units 
WHERE name IN ('vault.service', 'nomad.service', 'consul.service', 'docker.service', 'osqueryd.service')
ORDER BY name;`

	if output, err := cli.ExecString("osqueryi", "--line", serviceQuery); err == nil {
		fmt.Println(output)
	} else {
		logger.Warn("Failed to query services", zap.Error(err))
	}

	// 5. Check file system artifacts
	fmt.Println("\nFile System Artifacts:")
	fmt.Println("---------------------")

	fileQuery := `SELECT path, type, mode, uid, gid, size 
FROM file 
WHERE path IN ('/opt/eos', '/opt/vault', '/opt/nomad', '/etc/vault.d', '/etc/nomad.d', '/opt/clusterfuzz')
ORDER BY path;`

	if output, err := cli.ExecString("osqueryi", "--line", fileQuery); err == nil {
		fmt.Println(output)
	} else {
		logger.Warn("Failed to query files", zap.Error(err))
	}

	// 6. System resource usage
	fmt.Println("\nSystem Resources:")
	fmt.Println("----------------")

	resourceQuery := `SELECT * FROM system_info;`

	if output, err := cli.ExecString("osqueryi", "--line", resourceQuery); err == nil {
		lines := strings.Split(output, "\n")
		// Show only key metrics
		for _, line := range lines {
			if strings.Contains(line, "cpu_brand") ||
				strings.Contains(line, "physical_memory") ||
				strings.Contains(line, "hostname") {
				fmt.Println(line)
			}
		}
	}

	// Load average
	loadQuery := `SELECT * FROM load_average;`
	if output, err := cli.ExecString("osqueryi", "--line", loadQuery); err == nil {
		fmt.Println(output)
	}

	fmt.Println("\nVerification complete.")

	return nil
}

// TODO: refactor - move to pkg/verify/ or pkg/osquery/verify.go - Verification logic should be in pkg/
func verifyCleanState(_ *eos_io.RuntimeContext, cli *eos_cli.CLI, _ bool) error {

	fmt.Println("Verifying Clean State")
	fmt.Println("====================")
	fmt.Println()

	cleanState := true

	// Check for processes that shouldn't exist
	processQuery := `SELECT name, pid FROM processes 
WHERE name IN ('vault', 'nomad', 'consul', 'osqueryd');`

	if output, err := cli.ExecString("osqueryi", "--json", processQuery); err == nil {
		var results []map[string]interface{}
		if err := json.Unmarshal([]byte(output), &results); err == nil && len(results) > 0 {
			cleanState = false
			fmt.Println("✗ Found running processes:")
			for _, proc := range results {
				fmt.Printf("  - %s (PID: %v)\n", proc["name"], proc["pid"])
			}
		} else {
			fmt.Println("✓ No eos-managed processes running")
		}
	}

	// Check for packages
	packageQuery := `SELECT name, version FROM deb_packages 
WHERE name IN ('vault', 'nomad', 'consul', 'osquery');`

	if output, err := cli.ExecString("osqueryi", "--json", packageQuery); err == nil {
		var results []map[string]interface{}
		if err := json.Unmarshal([]byte(output), &results); err == nil && len(results) > 0 {
			cleanState = false
			fmt.Println("\n✗ Found installed packages:")
			for _, pkg := range results {
				fmt.Printf("  - %s (%s)\n", pkg["name"], pkg["version"])
			}
		} else {
			fmt.Println("✓ No eos-managed packages installed")
		}
	}

	// Check for directories
	dirs := []string{
		"/srv",
		"/opt/vault",
		"/opt/nomad",
		"/opt/clusterfuzz",
		"/var/lib/eos",
	}

	fmt.Println("\n✓ Checking directories:")
	foundDirs := false
	for _, dir := range dirs {
		if _, err := cli.ExecString("test", "-d", dir); err == nil {
			foundDirs = true
			cleanState = false
			fmt.Printf("  ✗ Found: %s\n", dir)
		}
	}

	if !foundDirs {
		fmt.Println("  ✓ No eos-managed directories found")
	}

	// Overall result
	fmt.Println("\nOverall Status:")
	fmt.Println("--------------")
	if cleanState {
		fmt.Println("✓ System is in clean state")
	} else {
		fmt.Println("✗ System has eos-managed components")
		fmt.Println("\nTo clean up, run: eos delete nuke --all")
	}

	return nil
}

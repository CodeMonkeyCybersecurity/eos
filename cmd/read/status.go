package read

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check status of eos-managed infrastructure",
	Long: `Quick status check of all eos-managed components.
Shows component health, service status, and basic connectivity tests.`,
	RunE:    eos_cli.Wrap(runStatus),
	Aliases: []string{"health", "check"},
}

func init() {
	ReadCmd.AddCommand(statusCmd)

	statusCmd.Flags().Bool("all", false, "Show status for all components")
	statusCmd.Flags().Bool("osquery", false, "Use OSQuery for verification")
}

func runStatus(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	showAll := cmd.Flag("all").Value.String() == "true"
	useOSQuery := cmd.Flag("osquery").Value.String() == "true"

	logger.Info("Checking infrastructure status",
		zap.Bool("show_all", showAll),
		zap.Bool("use_osquery", useOSQuery))

	cli := eos_cli.New(rc)

	// Quick status checks
	fmt.Println("EOS Infrastructure Status")
	fmt.Println("========================")
	fmt.Println()

	// Core services
	services := []struct {
		name    string
		service string
		command string
		port    string
	}{

		{"Vault", "vault", "vault", strconv.Itoa(shared.PortVault)},
		{"Nomad", "nomad", "nomad", "4646"},
		{"OSQuery", "osqueryd", "osqueryi", ""},
	}

	allHealthy := true

	for _, svc := range services {
		// Check if command exists
		cmdExists := false
		if _, err := cli.Which(svc.command); err == nil {
			cmdExists = true
		}

		if !cmdExists && !showAll {
			continue
		}

		// Check service status
		serviceStatus := "not installed"
		if cmdExists {
			if output, err := cli.ExecString("systemctl", "is-active", svc.service); err == nil {
				serviceStatus = strings.TrimSpace(output)
			} else {
				serviceStatus = "inactive"
			}
		}

		// Format status
		statusIcon := "✗"
		if serviceStatus == "active" {
			statusIcon = "✓"
		} else {
			allHealthy = false
		}

		fmt.Printf("%s %-15s: %s\n", statusIcon, svc.name, serviceStatus)

		// Additional checks for active services
		if serviceStatus == "active" && svc.port != "" {
			// Check if port is listening
			if output, err := cli.ExecString("ss", "-tlnp", "sport", "=", ":"+svc.port); err == nil && output != "" {
				fmt.Printf("  └─ Listening on port %s\n", svc.port)
			}
		}
	}

	fmt.Println()

	// Connectivity tests
	fmt.Println("Connectivity Tests:")
	fmt.Println("------------------")

	// Vault status
	if _, err := cli.Which("vault"); err == nil {
		fmt.Print("Vault API:           ")
		if output, err := cli.ExecString("vault", "status", "-format=json"); err == nil && output != "" {
			if strings.Contains(output, "initialized") {
				fmt.Println("✓ Responding")
			} else {
				fmt.Println("⚠ Not initialized")
			}
		} else {
			fmt.Println("✗ Not responding")
			allHealthy = false
		}
	}

	// Nomad status
	if _, err := cli.Which("nomad"); err == nil {
		fmt.Print("Nomad API:           ")
		if _, err := cli.ExecString("nomad", "status"); err == nil {
			fmt.Println("✓ Responding")
		} else {
			fmt.Println("✗ Not responding")
			allHealthy = false
		}
	}

	fmt.Println()

	// OSQuery verification if requested
	if useOSQuery && commandExists(cli, "osqueryi") {
		fmt.Println("OSQuery Verification:")
		fmt.Println("-------------------")

		query := `SELECT name, pid, state FROM processes WHERE name IN ('vault', 'nomad', 'osqueryd');`

		if output, err := cli.ExecString("osqueryi", "--line", query); err == nil {
			fmt.Println(output)
		} else {
			fmt.Println("✗ OSQuery verification failed")
		}
		fmt.Println()
	}

	// Overall status
	fmt.Println("Overall Status:")
	fmt.Println("--------------")
	if allHealthy {
		fmt.Println("✓ All systems operational")
	} else {
		fmt.Println("⚠ Some systems need attention")
		fmt.Println("\nTroubleshooting:")
		fmt.Println("• Check logs: journalctl -u [service-name]")
		fmt.Println("• Restart service: systemctl restart [service-name]")
		fmt.Println("• Re-run quickstart: eos create quickstart")
	}

	return nil
}

func commandExists(cli *eos_cli.CLI, cmd string) bool {
	_, err := cli.Which(cmd)
	return err == nil
}

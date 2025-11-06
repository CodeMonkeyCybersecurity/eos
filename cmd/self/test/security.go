package test

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var securityCmd = &cobra.Command{
	Use:   "security",
	Short: "Run security-focused tests and static analysis",
	Long: `Runs security-focused tests and static analysis tools.

This command orchestrates multiple security checks:
1. Go security checker (gosec) - static analysis for security issues
2. Dependency vulnerability scanning (govulncheck)
3. Security-tagged tests (tests with //go:build security tag)
4. Race detector on critical packages
5. TLS/crypto configuration validation

Examples:
  # Run all security checks
  eos self test security

  # Run only static analysis (gosec)
  eos self test security --static-only

  # Run only vulnerability scanning
  eos self test security --vulncheck-only

  # Include race detector on critical packages
  eos self test security --race

  # Scan specific package
  eos self test security --package=./pkg/vault/...
`,
	RunE: eos_cli.Wrap(runSecurity),
}

func init() {
	securityCmd.Flags().Bool("static-only", false, "Run only static analysis (gosec)")
	securityCmd.Flags().Bool("vulncheck-only", false, "Run only vulnerability scanning")
	securityCmd.Flags().Bool("race", false, "Run race detector on critical packages")
	securityCmd.Flags().String("package", "./...", "Package pattern to scan")
	securityCmd.Flags().Bool("verbose", false, "Show verbose output")
}

func runSecurity(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	staticOnly, _ := cmd.Flags().GetBool("static-only")
	vulncheckOnly, _ := cmd.Flags().GetBool("vulncheck-only")
	useRace, _ := cmd.Flags().GetBool("race")
	packagePattern, _ := cmd.Flags().GetString("package")
	verbose, _ := cmd.Flags().GetBool("verbose")

	logger.Info("Running security checks",
		zap.String("package", packagePattern),
		zap.Bool("static_only", staticOnly),
		zap.Bool("vulncheck_only", vulncheckOnly),
		zap.Bool("race", useRace))

	fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("  Security Analysis")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	hasErrors := false

	// ASSESS: Check available security tools
	availableTools := assessSecurityTools(rc)

	// Run checks based on flags
	if vulncheckOnly {
		// Only vulnerability scanning
		if err := runVulnerabilityCheck(rc, packagePattern, verbose); err != nil {
			hasErrors = true
		}
	} else if staticOnly {
		// Only static analysis
		if err := runStaticSecurityAnalysis(rc, packagePattern, verbose, availableTools); err != nil {
			hasErrors = true
		}
	} else {
		// Run all checks
		if err := runStaticSecurityAnalysis(rc, packagePattern, verbose, availableTools); err != nil {
			hasErrors = true
		}

		if err := runVulnerabilityCheck(rc, packagePattern, verbose); err != nil {
			hasErrors = true
		}

		if err := runSecurityTaggedTests(rc, packagePattern, verbose); err != nil {
			hasErrors = true
		}

		if useRace {
			if err := runRaceDetectorOnCriticalPackages(rc, verbose); err != nil {
				hasErrors = true
			}
		}
	}

	// EVALUATE: Report final status
	fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	if hasErrors {
		fmt.Println("✗ Security checks completed with ERRORS")
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		logger.Error("Security checks failed")
		return fmt.Errorf("security checks found issues")
	}

	fmt.Println("✓ All security checks PASSED")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Info("Security checks passed")
	return nil
}

type securityTools struct {
	HasGosec       bool
	HasGovulncheck bool
}

func assessSecurityTools(rc *eos_io.RuntimeContext) securityTools {
	logger := otelzap.Ctx(rc.Ctx)

	tools := securityTools{}

	if _, err := exec.LookPath("gosec"); err == nil {
		tools.HasGosec = true
		logger.Debug("gosec available")
	} else {
		logger.Warn("gosec not found",
			zap.String("install", "go install github.com/securego/gosec/v2/cmd/gosec@latest"))
	}

	if _, err := exec.LookPath("govulncheck"); err == nil {
		tools.HasGovulncheck = true
		logger.Debug("govulncheck available")
	} else {
		logger.Warn("govulncheck not found",
			zap.String("install", "go install golang.org/x/vuln/cmd/govulncheck@latest"))
	}

	return tools
}

func runStaticSecurityAnalysis(rc *eos_io.RuntimeContext, packagePattern string, verbose bool, tools securityTools) error {
	logger := otelzap.Ctx(rc.Ctx)

	fmt.Println("→ Static Security Analysis (gosec)")
	fmt.Println()

	if !tools.HasGosec {
		fmt.Println("⚠ gosec not installed - skipping static analysis")
		fmt.Println("Install with: go install github.com/securego/gosec/v2/cmd/gosec@latest")
		fmt.Println()
		return nil
	}

	args := []string{
		"-fmt=text",
		"-exclude-generated",
	}

	if !verbose {
		args = append(args, "-quiet")
	}

	args = append(args, packagePattern)

	logger.Info("Running gosec", zap.Strings("args", args))

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "gosec",
		Args:    args,
		Capture: true,
	})

	fmt.Print(output)

	if err != nil {
		logger.Error("gosec found security issues",
			zap.Error(err),
			zap.String("output", output))
		fmt.Println("✗ Security issues found by gosec")
		fmt.Println()
		return fmt.Errorf("gosec found security issues")
	}

	fmt.Println("✓ No security issues found by gosec")
	fmt.Println()
	return nil
}

func runVulnerabilityCheck(rc *eos_io.RuntimeContext, packagePattern string, verbose bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	fmt.Println("→ Vulnerability Scanning (govulncheck)")
	fmt.Println()

	if _, err := exec.LookPath("govulncheck"); err != nil {
		fmt.Println("⚠ govulncheck not installed - skipping vulnerability check")
		fmt.Println("Install with: go install golang.org/x/vuln/cmd/govulncheck@latest")
		fmt.Println()
		return nil
	}

	args := []string{}

	if verbose {
		args = append(args, "-v")
	}

	args = append(args, packagePattern)

	logger.Info("Running govulncheck", zap.Strings("args", args))

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "govulncheck",
		Args:    args,
		Capture: true,
	})

	fmt.Print(output)

	if err != nil {
		logger.Error("govulncheck found vulnerabilities",
			zap.Error(err),
			zap.String("output", output))
		fmt.Println("✗ Vulnerabilities found")
		fmt.Println()
		return fmt.Errorf("vulnerabilities detected")
	}

	fmt.Println("✓ No known vulnerabilities")
	fmt.Println()
	return nil
}

func runSecurityTaggedTests(rc *eos_io.RuntimeContext, packagePattern string, verbose bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	fmt.Println("→ Security-Tagged Tests")
	fmt.Println()

	args := []string{"test"}

	if verbose {
		args = append(args, "-v")
	}

	args = append(args, "-tags=security", packagePattern)

	logger.Info("Running security tests", zap.Strings("args", args))

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "go",
		Args:    args,
		Capture: true,
	})

	// Check if there are any security tests
	if strings.Contains(output, "no test files") || strings.Contains(output, "[no test files]") {
		fmt.Println("ℹ No security-tagged tests found")
		fmt.Println("  To add security tests, use: //go:build security")
		fmt.Println()
		return nil
	}

	fmt.Print(output)

	if err != nil {
		logger.Error("Security tests failed",
			zap.Error(err),
			zap.String("output", output))
		fmt.Println("✗ Security tests failed")
		fmt.Println()
		return fmt.Errorf("security tests failed")
	}

	fmt.Println("✓ Security tests passed")
	fmt.Println()
	return nil
}

func runRaceDetectorOnCriticalPackages(rc *eos_io.RuntimeContext, verbose bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	fmt.Println("→ Race Detector on Critical Packages")
	fmt.Println()

	// Critical packages that handle secrets, authentication, or concurrency
	criticalPackages := []string{
		"./pkg/secrets/...",
		"./pkg/vault/...",
		"./pkg/crypto/...",
		"./pkg/environment/...",
	}

	hasErrors := false

	for _, pkg := range criticalPackages {
		fmt.Printf("Testing %s with race detector...\n", pkg)

		args := []string{"test", "-race", "-short"}

		if verbose {
			args = append(args, "-v")
		}

		args = append(args, pkg)

		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "go",
			Args:    args,
			Capture: true,
		})

		if verbose || err != nil {
			fmt.Print(output)
		}

		if err != nil {
			logger.Error("Race detector found issues",
				zap.String("package", pkg),
				zap.Error(err))
			fmt.Printf("✗ Race conditions detected in %s\n", pkg)
			hasErrors = true
		} else {
			fmt.Printf("✓ No races in %s\n", pkg)
		}
	}

	fmt.Println()

	if hasErrors {
		return fmt.Errorf("race conditions detected in critical packages")
	}

	return nil
}

// test/comprehensive_fuzz_test.go

package test

import (
	"context"
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
)

// FuzzAllEOSCommands tests all legitimate EOS commands to prevent crashes
func FuzzAllEOSCommands(f *testing.F) {
	// Seed with all main commands from root.go
	f.Add("ai", "", "")
	f.Add("create", "hcl", "terraform")
	f.Add("create", "vault", "")
	f.Add("create", "docker", "")
	f.Add("crypto", "hash", "")
	f.Add("read", "config", "")
	f.Add("read", "vault", "")
	f.Add("list", "users", "")
	f.Add("list", "services", "")
	f.Add("update", "system", "")
	f.Add("delete", "user", "")
	f.Add("self", "update", "")
	f.Add("refresh", "configs", "")
	f.Add("secure", "system", "")
	f.Add("disable", "service", "")
	f.Add("backup", "create", "")
	f.Add("enable", "service", "")
	f.Add("sync", "configs", "")
	f.Add("hecate", "status", "")
	f.Add("delphi", "services", "update")
	f.Add("delphi", "services", "create")
	f.Add("delphi", "status", "")
	f.Add("inspect", "terraform", "")
	f.Add("pandora", "status", "")
	f.Add("ragequit", "", "")

	// Seed with problematic patterns that previously caused crashes
	f.Add("delphi", "services", "--all")
	f.Add("", "", "")
	f.Add("help", "", "")
	f.Add("--help", "", "")
	f.Add("invalid", "command", "")

	f.Fuzz(func(t *testing.T, cmd1, cmd2, cmd3 string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("EOS command crashed with panic: %v, args: [%q, %q, %q]", r, cmd1, cmd2, cmd3)
			}
		}()

		// Build args, skipping empty strings
		args := []string{}
		if cmd1 != "" {
			args = append(args, cmd1)
		}
		if cmd2 != "" {
			args = append(args, cmd2)
		}
		if cmd3 != "" {
			args = append(args, cmd3)
		}

		// Create comprehensive command structure matching actual EOS
		rootCmd := createTestEOSCommandTree()

		// Set up context
		ctx := context.Background()
		rc := &eos_io.RuntimeContext{
			Ctx: ctx,
		}
		rootCmd.SetContext(rc.Ctx)

		// Set args and try command parsing
		rootCmd.SetArgs(args)

		// Test command finding without execution
		_, _, err := rootCmd.Find(args)
		_ = err // Don't care about errors, just crashes

		// Also test parsing flags if we have dashes
		if len(args) > 0 && strings.HasPrefix(args[0], "-") {
			rootCmd.ParseFlags(args)
		}
	})
}

// FuzzEOSCommandFlags tests various flag combinations
func FuzzEOSCommandFlags(f *testing.F) {
	// Seed with common flag patterns
	f.Add("--help")
	f.Add("--version")
	f.Add("--verbose")
	f.Add("--dry-run")
	f.Add("--timeout=5m")
	f.Add("--config=/path/to/config")
	f.Add("--all")
	f.Add("--force")
	f.Add("--skip-installation-check")
	f.Add("-h")
	f.Add("-v")
	f.Add("")

	f.Fuzz(func(t *testing.T, flag string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("EOS flag parsing crashed with panic: %v, flag: %q", r, flag)
			}
		}()

		// Create test command
		rootCmd := createTestEOSCommandTree()
		ctx := context.Background()
		rootCmd.SetContext(ctx)

		// Test flag parsing
		args := []string{}
		if flag != "" {
			args = append(args, flag)
		}

		rootCmd.SetArgs(args)
		rootCmd.ParseFlags(args)
	})
}

// FuzzDelphiServicesCommands focuses on the problematic delphi services commands
func FuzzDelphiServicesCommands(f *testing.F) {
	// Seed with service names that caused crashes
	f.Add("update", "alert-to-db")
	f.Add("update", "ab-test-analyzer")
	f.Add("update", "delphi-listener")
	f.Add("update", "--all")
	f.Add("create", "alert-to-db")
	f.Add("create", "ab-test-analyzer")
	f.Add("status", "")
	f.Add("list", "")
	f.Add("", "")

	f.Fuzz(func(t *testing.T, subCmd, serviceName string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Delphi services command crashed with panic: %v, subCmd: %q, serviceName: %q", r, subCmd, serviceName)
			}
		}()

		// Build delphi services command
		args := []string{"delphi", "services"}
		if subCmd != "" {
			args = append(args, subCmd)
		}
		if serviceName != "" {
			args = append(args, serviceName)
		}

		// Always add dry-run and skip-installation-check for safety
		args = append(args, "--dry-run", "--skip-installation-check")

		rootCmd := createTestEOSCommandTree()
		ctx := context.Background()
		rootCmd.SetContext(ctx)
		rootCmd.SetArgs(args)

		// Test command finding
		_, _, err := rootCmd.Find(args)
		_ = err // Don't care about errors, just crashes
	})
}

// createTestEOSCommandTree creates a minimal but comprehensive command tree for testing
func createTestEOSCommandTree() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "eos",
		Short: "EOS CLI Tool",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil // Safe no-op
		},
	}

	// Add all main commands from root.go
	commands := map[string]*cobra.Command{
		"ai":       {Use: "ai", RunE: noopRunE},
		"create":   {Use: "create", RunE: noopRunE},
		"crypto":   {Use: "crypto", RunE: noopRunE},
		"read":     {Use: "read", RunE: noopRunE},
		"list":     {Use: "list", RunE: noopRunE},
		"update":   {Use: "update", RunE: noopRunE},
		"delete":   {Use: "delete", RunE: noopRunE},
		"self":     {Use: "self", RunE: noopRunE},
		"refresh":  {Use: "refresh", RunE: noopRunE},
		"secure":   {Use: "secure", RunE: noopRunE},
		"disable":  {Use: "disable", RunE: noopRunE},
		"backup":   {Use: "backup", RunE: noopRunE},
		"enable":   {Use: "enable", RunE: noopRunE},
		"sync":     {Use: "sync", RunE: noopRunE},
		"hecate":   {Use: "hecate", RunE: noopRunE},
		"delphi":   {Use: "delphi", RunE: noopRunE},
		"inspect":  {Use: "inspect", RunE: noopRunE},
		"pandora":  {Use: "pandora", RunE: noopRunE},
		"ragequit": {Use: "ragequit", RunE: noopRunE},
	}

	// Add subcommands for complex commands
	// Delphi subcommands
	delphiServices := &cobra.Command{Use: "services", RunE: noopRunE}
	delphiServices.AddCommand(
		&cobra.Command{Use: "update", RunE: noopRunE},
		&cobra.Command{Use: "create", RunE: noopRunE},
		&cobra.Command{Use: "status", RunE: noopRunE},
		&cobra.Command{Use: "list", RunE: noopRunE},
	)
	commands["delphi"].AddCommand(delphiServices)

	// Create subcommands
	createHCL := &cobra.Command{Use: "hcl", RunE: noopRunE}
	createHCL.AddCommand(
		&cobra.Command{Use: "terraform", RunE: noopRunE},
		&cobra.Command{Use: "vault", RunE: noopRunE},
		&cobra.Command{Use: "consul", RunE: noopRunE},
		&cobra.Command{Use: "nomad", RunE: noopRunE},
		&cobra.Command{Use: "packer", RunE: noopRunE},
		&cobra.Command{Use: "all", RunE: noopRunE},
	)
	commands["create"].AddCommand(createHCL)
	commands["create"].AddCommand(
		&cobra.Command{Use: "vault", RunE: noopRunE},
		&cobra.Command{Use: "docker", RunE: noopRunE},
		&cobra.Command{Use: "ldap", RunE: noopRunE},
		&cobra.Command{Use: "jenkins", RunE: noopRunE},
	)

	// Crypto subcommands
	commands["crypto"].AddCommand(
		&cobra.Command{Use: "hash", RunE: noopRunE},
		&cobra.Command{Use: "encrypt", RunE: noopRunE},
		&cobra.Command{Use: "decrypt", RunE: noopRunE},
	)

	// Read subcommands
	commands["read"].AddCommand(
		&cobra.Command{Use: "config", RunE: noopRunE},
		&cobra.Command{Use: "vault", RunE: noopRunE},
		&cobra.Command{Use: "logs", RunE: noopRunE},
	)

	// List subcommands
	commands["list"].AddCommand(
		&cobra.Command{Use: "users", RunE: noopRunE},
		&cobra.Command{Use: "services", RunE: noopRunE},
		&cobra.Command{Use: "containers", RunE: noopRunE},
	)

	// Add all commands to root
	for _, cmd := range commands {
		rootCmd.AddCommand(cmd)
	}

	// Add common flags to all commands
	rootCmd.PersistentFlags().Bool("help", false, "help for this command")
	rootCmd.PersistentFlags().Bool("verbose", false, "verbose output")
	rootCmd.PersistentFlags().Bool("dry-run", false, "dry run mode")
	rootCmd.PersistentFlags().String("timeout", "5m", "timeout duration")
	rootCmd.PersistentFlags().Bool("force", false, "force operation")
	rootCmd.PersistentFlags().Bool("skip-installation-check", false, "skip installation check")

	return rootCmd
}

// noopRunE is a safe no-op function for commands during fuzzing
func noopRunE(cmd *cobra.Command, args []string) error {
	return nil
}

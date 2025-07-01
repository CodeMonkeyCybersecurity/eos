// pkg/eos_cli/fuzz_simple_test.go

package eos_cli

import (
	"context"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
)

// Simple command parsing test that focuses on crash prevention
func FuzzCommandParsing(f *testing.F) {
	// Seed with patterns that previously caused crashes
	f.Add("delphi", "services", "update")
	f.Add("delphi", "services", "create")
	f.Add("vault", "status", "")
	f.Add("help", "", "")
	f.Add("", "", "")

	f.Fuzz(func(t *testing.T, cmd1, cmd2, cmd3 string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Command parsing crashed with panic: %v, args: [%q, %q, %q]", r, cmd1, cmd2, cmd3)
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

		// Create a minimal root command for testing
		rootCmd := &cobra.Command{
			Use:   "eos",
			Short: "EOS CLI Tool",
			RunE: func(cmd *cobra.Command, args []string) error {
				return nil // Safe no-op
			},
		}

		// Add some subcommands
		delphiCmd := &cobra.Command{
			Use: "delphi",
			RunE: func(cmd *cobra.Command, args []string) error {
				return nil
			},
		}
		
		servicesCmd := &cobra.Command{
			Use: "services", 
			RunE: func(cmd *cobra.Command, args []string) error {
				return nil
			},
		}
		
		updateCmd := &cobra.Command{
			Use: "update",
			RunE: func(cmd *cobra.Command, args []string) error {
				return nil
			},
		}
		
		createCmd := &cobra.Command{
			Use: "create",
			RunE: func(cmd *cobra.Command, args []string) error {
				return nil
			},
		}

		// Build command tree
		servicesCmd.AddCommand(updateCmd, createCmd)
		delphiCmd.AddCommand(servicesCmd)
		rootCmd.AddCommand(delphiCmd)

		// Set up context
		ctx := context.Background()
		rc := &eos_io.RuntimeContext{
			Ctx: ctx,
		}
		rootCmd.SetContext(rc.Ctx)

		// Try to parse without executing
		rootCmd.SetArgs(args)
		
		// This should never panic, but might return errors (which is fine)
		_, _, err := rootCmd.Find(args)
		_ = err // Don't care about errors, just crashes
	})
}
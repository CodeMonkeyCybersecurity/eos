/* pkg/execute/execute.go */
package execute

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/errorer"
)

//
//---------------------------- COMMAND EXECUTION ---------------------------- //
//

// Execute runs a command with separate arguments.
func Execute(command string, args ...string) error {
	fmt.Printf("➡ Executing command: %s %s\n", command, strings.Join(args, " "))
	cmd := exec.Command(command, args...)
	output, err := cmd.CombinedOutput()
	fmt.Print(string(output)) // Always show output

	if err != nil {
		return fmt.Errorf("command failed: %s\noutput:\n%s", err, string(output))
	}
	return nil
}

func ExecuteShell(command string) error {
	fmt.Printf("➡ Executing shell command: %s\n", command)
	cmd := exec.Command("bash", "-c", command)
	output, err := cmd.CombinedOutput()
	fmt.Print(string(output))

	if err != nil {
		return fmt.Errorf("shell command failed: %s\noutput:\n%s", err, string(output))
	}
	return nil
}

func ExecuteInDir(dir, command string, args ...string) error {
	fmt.Printf("➡ Executing in %s: %s %s\n", dir, command, strings.Join(args, " "))
	cmd := exec.Command(command, args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	fmt.Print(string(output))

	if err != nil {
		return fmt.Errorf("command in directory failed: %s\noutput:\n%s", err, string(output))
	}
	return nil
}

func ExecuteRaw(command string, args ...string) *exec.Cmd {
	fmt.Printf("➡ Executing (raw): %s %s\n", command, strings.Join(args, " "))
	return exec.Command(command, args...)
}

// ExecuteAndLog runs a command and streams stdout/stderr directly.
// It returns an error if the command fails.
func ExecuteAndLog(name string, args ...string) error {
	fmt.Printf("🚀 Running: %s %s\n", name, joinArgs(args))

	cmd := exec.Command(name, args...)
	var outputBuf bytes.Buffer
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fullOutput := outputBuf.String()
		// Extract a concise error message—e.g., the first error line
		summary := errorer.ExtractSummary(fullOutput)
		return fmt.Errorf("command failed: %s %s: %w - %s", name, joinArgs(args), err, summary)
	}

	fmt.Printf("✅ Completed: %s %s\n", name, joinArgs(args))
	return nil
}

// joinArgs formats arguments for display
func joinArgs(args []string) string {
	return shellQuote(args)
}

// shellQuote ensures args are properly quoted for visibility
func shellQuote(args []string) string {
	quoted := ""
	for _, arg := range args {
		quoted += fmt.Sprintf("'%s' ", arg)
	}
	return quoted
}

package execute

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eoserr"
)

//
//---------------------------- COMMAND EXECUTION ---------------------------- //
//

// Execute runs a command with separate arguments and returns a rich error if it fails.
func Execute(command string, args ...string) error {
	cmdStr := fmt.Sprintf("%s %s", command, strings.Join(args, " "))
	fmt.Printf("➡ Executing command: %s\n", cmdStr)

	cmd := exec.Command(command, args...)
	output, err := cmd.CombinedOutput()
	fmt.Print(string(output))

	if err != nil {
		return fmt.Errorf("❌ Command failed: %s\n%s", cmdStr, string(output))
	}
	fmt.Printf("✅ Command completed: %s\n", cmdStr)
	return nil
}

// ExecuteShell runs a shell command string through Bash.
func ExecuteShell(command string) error {
	fmt.Printf("➡ Executing shell command: %s\n", command)
	cmd := exec.Command("bash", "-c", command)
	output, err := cmd.CombinedOutput()
	fmt.Print(string(output))

	if err != nil {
		return fmt.Errorf("❌ Shell command failed: %w\noutput:\n%s", err, string(output))
	}
	fmt.Printf("✅ Shell command completed: %s\n", command)
	return nil
}

// ExecuteInDir runs a command from a specific working directory.
func ExecuteInDir(dir, command string, args ...string) error {
	fmt.Printf("➡ Executing in %s: %s %s\n", dir, command, strings.Join(args, " "))
	cmd := exec.Command(command, args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	fmt.Print(string(output))

	if err != nil {
		return fmt.Errorf("❌ Command in directory failed: %w\noutput:\n%s", err, string(output))
	}
	fmt.Printf("✅ Directory command completed: %s\n", command)
	return nil
}

// ExecuteRaw returns an *exec.Cmd for manual execution and handling.
func ExecuteRaw(command string, args ...string) *exec.Cmd {
	return exec.Command(command, args...)
}

// ExecuteAndLog runs a command and streams stdout/stderr live.
func ExecuteAndLog(name string, args ...string) error {
	fmt.Printf("🚀 Running: %s %s\n", name, joinArgs(args))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)

	var outputBuf bytes.Buffer
	cmd.Stdout = io.MultiWriter(os.Stdout, &outputBuf)
	cmd.Stderr = io.MultiWriter(os.Stderr, &outputBuf)

	if err := cmd.Run(); err != nil {
		fullOutput := outputBuf.String()
		summary := eoserr.ExtractSummary(fullOutput, 2)
		return fmt.Errorf("❌ Command failed: %s %s: %w - %s", name, joinArgs(args), err, summary)
	}

	fmt.Printf("✅ Completed: %s %s\n", name, joinArgs(args))
	return nil
}

// joinArgs formats arguments for display.
func joinArgs(args []string) string {
	return shellQuote(args)
}

// shellQuote ensures args are properly quoted for visibility.
func shellQuote(args []string) string {
	var quoted []string
	for _, arg := range args {
		quoted = append(quoted, fmt.Sprintf("'%s'", arg))
	}
	return strings.Join(quoted, " ")
}

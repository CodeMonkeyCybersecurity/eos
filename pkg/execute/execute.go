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
)

// CommandError wraps errors from command execution.
type CommandError struct {
	Command string
	Output  string
	Err     error
}

func (e *CommandError) Error() string {
	return fmt.Sprintf("command failed: %s\nerror: %v\noutput:\n%s", e.Command, e.Err, e.Output)
}

func (e *CommandError) Unwrap() error {
	return e.Err
}

// Execute runs a command with arguments.
func Execute(command string, args ...string) error {
	return runCommand(command, args, "", false)
}

// ExecuteShell runs a shell command string through bash.
func ExecuteShell(command string) error {
	return runCommand("bash", []string{"-c", command}, "", false)
}

// ExecuteInDir runs a command in a specific directory.
func ExecuteInDir(dir, command string, args ...string) error {
	return runCommand(command, args, dir, false)
}

// ExecuteSudo runs a command with sudo.
func ExecuteSudo(command string, args ...string) error {
	fullArgs := append([]string{command}, args...)
	return runCommand("sudo", fullArgs, "", false)
}

// ExecuteAndLog streams stdout/stderr live.
func ExecuteAndLog(command string, args ...string) error {
	return runCommand(command, args, "", true)
}

// ExecuteRaw returns an *exec.Cmd for advanced use.
func ExecuteRaw(command string, args ...string) *exec.Cmd {
	return exec.Command(command, args...)
}

// runCommand executes a command and optionally streams output.
func runCommand(command string, args []string, dir string, stream bool) error {
	cmdStr := fmt.Sprintf("%s %s", command, shellQuote(args))
	fmt.Printf("➡ Executing: %s\n", cmdStr)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, command, args...)
	if dir != "" {
		cmd.Dir = dir
	}

	var outputBuf bytes.Buffer
	if stream {
		cmd.Stdout = io.MultiWriter(os.Stdout, &outputBuf)
		cmd.Stderr = io.MultiWriter(os.Stderr, &outputBuf)
	} else {
		cmd.Stdout = &outputBuf
		cmd.Stderr = &outputBuf
	}

	err := cmd.Run()
	output := outputBuf.String()
	if err != nil {
		return &CommandError{Command: cmdStr, Output: output, Err: err}
	}

	fmt.Printf("✅ Completed: %s\n", cmdStr)
	return nil
}

// shellQuote safely quotes command-line arguments.
func shellQuote(args []string) string {
	var quoted []string
	for _, arg := range args {
		if strings.ContainsAny(arg, " \t\"'") {
			arg = fmt.Sprintf("'%s'", strings.ReplaceAll(arg, "'", "'\"'\"'"))
		}
		quoted = append(quoted, arg)
	}
	return strings.Join(quoted, " ")
}
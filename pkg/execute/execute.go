// pkg/execute/execute.go
package execute

import (
	"fmt"
	"os/exec"
	"strings"
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

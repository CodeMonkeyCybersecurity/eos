// pkg/exec.go
package execute

import (
	"fmt"
	"os/exec"

	"eos/pkg/logger"

	"go.uber.org/zap"
)

//
//---------------------------- COMMAND EXECUTION ---------------------------- //
//

// Execute runs a command with separate arguments.
func Execute(command string, args ...string) error {
	logger.Debug("Executing command", zap.String("command", command), zap.Strings("args", args))

	cmd := exec.Command(command, args...)
	output, err := cmd.CombinedOutput() // Captures both stdout and stderr
	fmt.Println(string(output))         // Always print command output for visibility

	if err != nil {
		logger.Error("Command execution failed", zap.String("command", command), zap.Strings("args", args), zap.Error(err), zap.String("output", string(output)))
		return fmt.Errorf("command failed: %s, output: %s", err, output)
	}

	logger.Info("Command executed successfully", zap.String("command", command), zap.String("output", string(output)))
	return nil
}

// ExecuteShell runs a shell command with pipes (`| grep`).
func ExecuteShell(command string) error {
	logger.Debug("Executing shell command", zap.String("command", command))

	cmd := exec.Command("bash", "-c", command)
	output, err := cmd.CombinedOutput() // Capture full output
	fmt.Println(string(output))         // Print output for visibility

	if err != nil {
		logger.Error("Shell command execution failed", zap.String("command", command), zap.Error(err), zap.String("output", string(output)))
		return fmt.Errorf("shell command failed: %s, output: %s", err, output)
	}

	logger.Info("Shell command executed successfully", zap.String("command", command), zap.String("output", string(output)))
	return nil
}

func ExecuteInDir(dir, command string, args ...string) error {
	logger.Debug("Executing command in directory", zap.String("directory", dir), zap.String("command", command), zap.Strings("args", args))

	cmd := exec.Command(command, args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput() // Capture output
	fmt.Println(string(output))         // Print output for visibility

	if err != nil {
		logger.Error("Command execution failed in directory",
			zap.String("directory", dir),
			zap.String("command", command),
			zap.Strings("args", args),
			zap.Error(err),
			zap.String("output", string(output)),
		)
		return fmt.Errorf("command in directory failed: %s, output: %s", err, output)
	}

	logger.Info("Command executed successfully in directory",
		zap.String("directory", dir),
		zap.String("command", command),
		zap.String("output", string(output)),
	)
	return nil
}

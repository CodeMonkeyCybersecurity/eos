package main

import (
	"log"
	"path/filepath"

	"eos/pkg/utils"
)

func main() {
	// Paths for configuration and log files
	configPath := filepath.Join("..", "..", "config", "default.yaml") // Adjust path as needed
	logFilePath := "/tmp/test_logger.log"

	// Initialize the logger
	err := utils.InitializeLogger(configPath, logFilePath, utils.DebugLevel, true)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	// Get the global logger instance
	logger := utils.GetLogger()

	// Test logging different levels
	logger.Debug("This is a DEBUG message")
	logger.Info("This is an INFO message")
	logger.Warn("This is a WARN message")
	logger.Error("This is an ERROR message")
	logger.Critical("This is a CRITICAL message")
}

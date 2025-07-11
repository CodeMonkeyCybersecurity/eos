package diagnostics

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ragequit/system"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CheckQueues checks message queue status
// Migrated from cmd/ragequit/ragequit.go checkQueues
func CheckQueues(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Prepare for queue checking
	logger.Info("Assessing message queue status")
	
	homeDir := system.GetHomeDir()
	outputFile := filepath.Join(homeDir, "ragequit-queues.txt")
	
	var output strings.Builder
	output.WriteString("=== Queue Diagnostics ===\n")
	output.WriteString(fmt.Sprintf("Timestamp: %s\n\n", time.Now().Format(time.RFC3339)))
	
	// INTERVENE - Check various queue systems
	logger.Debug("Checking message queue systems")
	
	// RabbitMQ
	if system.CommandExists("rabbitmqctl") {
		output.WriteString("=== RabbitMQ Status ===\n")
		if rmqStatus := system.RunCommandWithTimeout("rabbitmqctl", []string{"status"}, 10*time.Second); rmqStatus != "" {
			output.WriteString(rmqStatus)
			output.WriteString("\n")
		}
		
		if rmqQueues := system.RunCommandWithTimeout("rabbitmqctl", []string{"list_queues"}, 5*time.Second); rmqQueues != "" {
			output.WriteString("\n=== RabbitMQ Queues ===\n")
			output.WriteString(rmqQueues)
			output.WriteString("\n")
		}
	} else {
		logger.Debug("RabbitMQ not found")
	}
	
	// Redis
	if system.CommandExists("redis-cli") {
		output.WriteString("\n=== Redis Status ===\n")
		if redisInfo := system.RunCommandWithTimeout("redis-cli", []string{"INFO"}, 5*time.Second); redisInfo != "" {
			output.WriteString(redisInfo)
			output.WriteString("\n")
		}
	} else {
		logger.Debug("Redis not found")
	}
	
	// Kafka
	if system.FileExists("/opt/kafka") || system.CommandExists("kafka-topics.sh") {
		output.WriteString("\n=== Kafka Status ===\n")
		if kafkaTopics := system.RunCommandWithTimeout("kafka-topics.sh", 
			[]string{"--list", "--bootstrap-server", "localhost:9092"}, 5*time.Second); kafkaTopics != "" {
			output.WriteString("Kafka Topics:\n")
			output.WriteString(kafkaTopics)
			output.WriteString("\n")
		}
	} else {
		logger.Debug("Kafka not found")
	}
	
	// System message queues (IPC)
	output.WriteString("\n=== System Message Queues ===\n")
	if ipcsOutput := system.RunCommandWithTimeout("ipcs", []string{"-q"}, 5*time.Second); ipcsOutput != "" {
		output.WriteString(ipcsOutput)
		output.WriteString("\n")
	}
	
	// EVALUATE - Write results
	if err := os.WriteFile(outputFile, []byte(output.String()), 0644); err != nil {
		return fmt.Errorf("failed to write queue diagnostics: %w", err)
	}
	
	logger.Info("Queue diagnostics completed",
		zap.String("output_file", outputFile))
	
	return nil
}
package diagnostics

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ragequit"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ragequit/system"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DetectEnvironment detects and logs the system environment
// Migrated from cmd/ragequit/ragequit.go detectEnvironment
func DetectEnvironment(rc *eos_io.RuntimeContext) (*ragequit.EnvironmentInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Prepare for environment detection
	logger.Info("Assessing system environment")

	homeDir := system.GetHomeDir()
	outputFile := filepath.Join(homeDir, "ragequit-environment.txt")

	envInfo := &ragequit.EnvironmentInfo{
		Type:     "Unknown",
		Metadata: make(map[string]string),
	}

	var output strings.Builder
	output.WriteString("=== Environment Detection ===\n")

	// INTERVENE - Detect container environment
	logger.Debug("Detecting container environment")

	if shared.FileExists("/.dockerenv") {
		envInfo.Type = "Docker"
		output.WriteString("Environment: Docker Container\n")
		if dockerInfo := system.RunCommandWithTimeout("docker", []string{"info"}, 5*time.Second); dockerInfo != "" {
			output.WriteString(dockerInfo)
			envInfo.Metadata["docker_info"] = dockerInfo
		}
	} else if shared.FileExists("/run/.containerenv") {
		envInfo.Type = "Podman"
		output.WriteString("Environment: Podman Container\n")
	} else if system.ContainsString("/proc/1/cgroup", "kubernetes") {
		envInfo.Type = "Kubernetes"
		output.WriteString("Environment: Kubernetes Pod\n")
		if k8sInfo := system.RunCommandWithTimeout("kubectl", []string{"get", "pods", "--all-namespaces"}, 5*time.Second); k8sInfo != "" {
			output.WriteString(k8sInfo)
			envInfo.Metadata["k8s_pods"] = k8sInfo
		}
	} else {
		envInfo.Type = "BareMetal"
		output.WriteString("Environment: Bare Metal/VM\n")
	}

	// Detect cloud provider
	logger.Debug("Detecting cloud provider")

	if system.CommandExists("ec2-metadata") {
		envInfo.CloudProvider = "AWS"
		output.WriteString("Cloud: AWS EC2\n")
		if awsInfo := system.RunCommandWithTimeout("ec2-metadata", []string{"--all"}, 5*time.Second); awsInfo != "" {
			output.WriteString(awsInfo)
			envInfo.Metadata["aws_metadata"] = awsInfo
		}
	} else if system.ContainsString("/sys/class/dmi/id/product_name", "Google") {
		envInfo.CloudProvider = "GCP"
		output.WriteString("Cloud: Google Cloud\n")
	} else if system.ContainsString("/sys/class/dmi/id/sys_vendor", "Microsoft Corporation") {
		envInfo.CloudProvider = "Azure"
		output.WriteString("Cloud: Azure\n")
	} else {
		envInfo.CloudProvider = "None"
	}

	// EVALUATE - Write results
	if err := os.WriteFile(outputFile, []byte(output.String()), 0644); err != nil {
		return nil, fmt.Errorf("failed to write environment detection results: %w", err)
	}

	logger.Info("Environment detection completed",
		zap.String("type", envInfo.Type),
		zap.String("cloud", envInfo.CloudProvider),
		zap.String("output_file", outputFile))

	return envInfo, nil
}

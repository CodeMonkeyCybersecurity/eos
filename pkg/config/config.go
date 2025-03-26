// pkg/config/config.go
package config

import (
    "eos/pkg/logger"
    "go.uber.org/zap"
)

var Log *zap.Logger // Global logger

// DelphiListener virtual environment path
const VenvPath = "/opt/delphi_venv"

// Wazuh DockerListener script path
const DockerListener = "/var/ossec/wodles/docker/DockerListener"

// Umami install dir
const UmamiDir = "/opt/umami"

// Umami install dir
const JenkinsDir = "/opt/jenkins"

// Treecat
const MaxPreviewSize = 5 * 1024       // 5KB max preview
const MaxPreviewLines = 100           // 100 lines max

func InitConfig() {
    Log = logger.GetLogger() // Initialize logger once
}

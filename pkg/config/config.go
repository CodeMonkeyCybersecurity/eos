// pkg/config/config.go

package config

import (
    "eos/pkg/logger"
    "go.uber.org/zap"
)

var Log *zap.Logger // Global logger

// DelphiListener virtual environment path
const (
    VenvPath             = "/opt/delphi_venv"
    DockerListener       = "/var/ossec/wodles/docker/DockerListener" // Wazuh DockerListener script path
    UmamiDir             = "/opt/umami" // Umami install dir
    JenkinsDir           = "/opt/jenkins" // Jenkins install dir
    ZabbixDir            = "/opt/zabbix"
	ZabbixComposeYML     = "/opt/zabbix/zabbix-docker-compose.yml"
    MaxPreviewSize = 5 * 1024       // Treecat - 5KB max preview
    MaxPreviewLines = 100           // Treecat - 100 lines max
)

func InitConfig() {
    Log = logger.GetLogger() // Initialize logger once
}

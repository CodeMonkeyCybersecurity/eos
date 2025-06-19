// pkg/utils/read.go

package utils

import (
	"context"
	"os"
	"strings"
	
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func InspectCertificates(ctx context.Context) {
	logger := otelzap.Ctx(ctx)
	certsDir := "/opt/hecate/certs"
	
	logger.Info("🔍 Inspecting Certificates", zap.String("directory", certsDir))
	
	files, err := os.ReadDir(certsDir)
	if err != nil {
		logger.Error("❌ Error reading certificates directory", zap.String("directory", certsDir), zap.Error(err))
		return
	}
	
	if len(files) == 0 {
		logger.Info("📂 No certificates found", zap.String("directory", certsDir))
		return
	}
	
	logger.Info("📋 Found certificates", zap.Int("count", len(files)))
	for _, file := range files {
		logger.Info("📄 Certificate file", zap.String("filename", file.Name()))
	}
}

func InspectDockerCompose(ctx context.Context) {
	logger := otelzap.Ctx(ctx)
	configFile := "/opt/hecate/docker-compose.yml"
	
	logger.Info("🔍 Inspecting docker-compose file", zap.String("file", configFile))
	
	data, err := os.ReadFile(configFile)
	if err != nil {
		logger.Error("❌ Error reading docker-compose file", zap.String("file", configFile), zap.Error(err))
		return
	}
	
	logger.Info("📄 Docker-compose file contents", zap.String("content", string(data)))
}

func InspectEosConfig(ctx context.Context) {
	logger := otelzap.Ctx(ctx)
	confDir := "/opt/hecate/assets/conf.d"
	
	logger.Info("🔍 Inspecting Eos backend configuration", zap.String("directory", confDir))
	
	files, err := os.ReadDir(confDir)
	if err != nil {
		logger.Error("❌ Error reading configuration directory", zap.String("directory", confDir), zap.Error(err))
		return
	}
	
	var configFiles []string
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".conf") {
			configFiles = append(configFiles, file.Name())
		}
	}
	
	if len(configFiles) == 0 {
		logger.Info("📂 No Eos configuration files found", zap.String("directory", confDir))
		return
	}
	
	logger.Info("📋 Found Eos configuration files", zap.Strings("files", configFiles))
}

func InspectNginxDefaults(ctx context.Context) {
	logger := otelzap.Ctx(ctx)
	configFile := "/opt/hecate/nginx.conf"
	
	logger.Info("🔍 Inspecting Nginx configuration", zap.String("file", configFile))
	
	data, err := os.ReadFile(configFile)
	if err != nil {
		logger.Error("❌ Error reading Nginx configuration", zap.String("file", configFile), zap.Error(err))
		return
	}
	
	logger.Info("📄 Nginx configuration contents", zap.String("content", string(data)))
}

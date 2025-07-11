package services

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// GetFileInfo retrieves file information
// Migrated from cmd/read/pipeline_services.go getFileInfo
func GetFileInfo(rc *eos_io.RuntimeContext, path string) FileInfo {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Prepare file information retrieval
	logger.Debug("Assessing file information retrieval",
		zap.String("path", path))
	
	info := FileInfo{
		Permissions: "unknown",
		Size:        "unknown",
		Modified:    "unknown",
	}

	// INTERVENE - Get file information
	stat, err := os.Stat(path)
	if err != nil {
		logger.Debug("File not accessible",
			zap.String("path", path),
			zap.Error(err))
		return info
	}

	info.Permissions = stat.Mode().String()
	info.Size = fmt.Sprintf("%d bytes", stat.Size())
	info.Modified = stat.ModTime().Format("2006-01-02 15:04:05")

	// EVALUATE - Log successful file information retrieval
	logger.Debug("File information retrieved successfully",
		zap.String("path", path),
		zap.String("permissions", info.Permissions),
		zap.String("size", info.Size),
		zap.String("modified", info.Modified))

	return info
}
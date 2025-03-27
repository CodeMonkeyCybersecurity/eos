// pkg/utils/asset.go
package utils

import (
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"
)

// ReplacePlaceholders opens the file at filePath, replaces placeholders with provided values, and writes back.
func ReplacePlaceholders(filePath, baseDomain, backendIP string) error {
	log.Info("Reading file", zap.String("filePath", filePath))

	contentBytes, err := os.ReadFile(filePath)
	if err != nil {
		log.Error("Error reading file", zap.String("filePath", filePath), zap.Error(err))
		return fmt.Errorf("error reading file %s: %w", filePath, err)
	}
	content := string(contentBytes)

	log.Info("Replacing placeholders", zap.String("filePath", filePath))

	content = strings.ReplaceAll(content, "${BASE_DOMAIN}", baseDomain)
	content = strings.ReplaceAll(content, "${backendIP}", backendIP)

	log.Info("Writing updated content to file", zap.String("filePath", filePath))

	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		log.Error("Error writing file", zap.String("filePath", filePath), zap.Error(err))
		return fmt.Errorf("error writing file %s: %w", filePath, err)
	}

	log.Info("Successfully updated file", zap.String("filePath", filePath))
	return nil
}

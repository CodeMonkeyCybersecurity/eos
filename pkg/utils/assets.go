// pkg/utils/asset.go
package utils

import (
	"fmt"
	"os"
	"strings"
)

// ReplacePlaceholders opens the file at filePath, replaces placeholders with provided values, and writes back.
func ReplacePlaceholders(filePath, baseDomain, backendIP string) error {
	contentBytes, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("error reading file %s: %w", filePath, err)
	}
	content := string(contentBytes)
	content = strings.ReplaceAll(content, "${BASE_DOMAIN}", baseDomain)
	content = strings.ReplaceAll(content, "${backendIP}", backendIP)
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		return fmt.Errorf("error writing file %s: %w", filePath, err)
	}
	return nil
}

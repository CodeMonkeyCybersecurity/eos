//pkg/parse/json.go

package parse

import (
	"os"
	"path/filepath"
	"strings"
)

func ExpandHome(path string) string {
	if strings.HasPrefix(path, "~") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, strings.TrimPrefix(path, "~"))
		}
	}
	return path
}

func SplitPathList(list string) []string {
	sep := ":"
	if strings.Contains(list, ";") && !strings.Contains(list, ":") {
		sep = ";"
	}
	return strings.Split(list, sep)
}
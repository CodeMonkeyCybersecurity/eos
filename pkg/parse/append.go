// pkg/parse/append.go

package parse

import (
	"os"
	"strings"
)

// appendIfMissing ensures a line is present in a file.
func AppendIfMissing(path, line string) error {
	content, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if strings.Contains(string(content), line) {
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = f.WriteString("\n" + line + "\n")
	return err
}

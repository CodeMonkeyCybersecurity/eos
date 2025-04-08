/* pkg/logger/reader.go
 */

package logger

import (
	"os"
)

// ReadLogFile returns the contents of a given log file.
func readLogFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

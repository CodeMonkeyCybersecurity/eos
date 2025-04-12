/* pkg/system/checker.go */
package system

import (
	"os"
)

// Exists returns true if the file or directory at the given path exists.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil || !os.IsNotExist(err)
}

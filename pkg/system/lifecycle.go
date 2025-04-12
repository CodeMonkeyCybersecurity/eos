/* pkg/system/lifecycle.go */

package system

import (
	"fmt"
	"os"
)

// RemoveWithLog deletes a file or directory if it exists, with descriptive logging.
func Rm(path, label string) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		fmt.Printf("⚠️  %s not found: %s\n", label, path)
		return nil
	}
	if err != nil {
		fmt.Printf("❌ Error accessing %s (%s): %v\n", label, path, err)
		return nil
	}

	if info.IsDir() {
		fmt.Printf("🧹 Removing directory (%s): %s\n", label, path)
		err = os.RemoveAll(path)
	} else {
		fmt.Printf("🧹 Removing file (%s): %s\n", label, path)
		err = os.Remove(path)
	}

	if err != nil {
		fmt.Printf("❌ Failed to remove %s (%s): %v\n", label, path, err)
	} else {
		fmt.Printf("✅ %s removed: %s\n", label, path)
		return nil
	}
	return nil
}

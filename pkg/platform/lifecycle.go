/* pkg/platform/lifecycle.go */

package platform

import (
	"fmt"
	"os"
)

func CleanupFile(path string) {
	fmt.Printf("🧹 Removing sensitive file: %s\n", path)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		fmt.Printf("❌ Failed to delete %s: %v\n", path, err)
	} else {
		fmt.Printf("✅ %s deleted successfully.\n", path)
	}
}

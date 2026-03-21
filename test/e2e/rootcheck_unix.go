//go:build (e2e || e2e_smoke) && !windows

package e2e

import "os"

func currentProcessIsRoot() bool {
	return os.Geteuid() == 0
}

//go:build (e2e || e2e_smoke) && windows

package e2e

func currentProcessIsRoot() bool {
	return false
}

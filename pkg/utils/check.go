// pkg/utils/check.go

package utils

func IsValidApp(app string, validApps []string) bool {
	for _, valid := range validApps {
		if app == valid {
			return true
		}
	}
	return false
}

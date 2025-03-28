// pkg/utils/utils.go

package utils

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/config"
)

//
//---------------------------- FACT CHECKING ---------------------------- //
//

// ✅ Moved here since it may be used in multiple commands
func IsValidApp(app string) bool {
	for _, validApp := range config.GetSupportedAppNames() {
		if app == validApp {
			return true
		}
	}
	return false
}

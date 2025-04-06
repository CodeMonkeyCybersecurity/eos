// pkg/platform/admin.go
package platform

import (
	"bufio"
	"os"
	"strings"
)

func GuessAdminGroup() string {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return "sudo"
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var idLike string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "ID_LIKE=") {
			idLike = strings.Trim(strings.SplitN(line, "=", 2)[1], `"`)
			break
		}
	}
	if strings.Contains(idLike, "rhel") || strings.Contains(idLike, "fedora") {
		return "wheel"
	}
	return "sudo"
}

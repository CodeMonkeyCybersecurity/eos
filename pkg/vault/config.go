/* pkg/vault/config.go */

package vault

import (
	"fmt"
	"os"
)

func ResolveVaultConfigDir(distro string) string {
	switch distro {
	case "debian", "rhel":
		return VaultConfigDirDebian
	default:
		return VaultConfigDirSnap
	}
}

func GetVaultAddr() string {
	if addr := os.Getenv("VAULT_ADDR"); addr != "" {
		return addr
	}
	return VaultDefaultAddr
}

func RenderVaultConfig(addr string) string {
	return fmt.Sprintf(`
listener "tcp" {
  address     = "0.0.0.0:%s"
  tls_disable = 1
}
storage "file" {
  path = "%s"
}
disable_mlock = true
api_addr = "%s"
ui = true
`, VaultDefaultPort, VaultDataPath, addr)
}

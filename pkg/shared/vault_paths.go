// pkg/shared/vault_paths.go
package shared

const (
	// General
	LocalhostSAN          = "127.0.0.1"
	VaultDefaultPort      = "8179"
	VaultWebPortTCP       = VaultDefaultPort + "/tcp"
	ListenerAddr          = "127.0.0.1:" + VaultDefaultPort
	VaultDefaultAddr      = "https://%s:" + VaultDefaultPort
	VaultDefaultLocalAddr = "https://127.0.0.1:" + VaultDefaultPort

	// TLS
	// TLSDir is the directory for Vault TLS certificate files.
	// TLSKey and TLSCrt represent the file paths to the private key and certificate.
	TLSDir = "/opt/vault/tls/"
	TLSKey = TLSDir + "tls.key"
	TLSCrt = TLSDir + "tls.crt"

	// Storage
	VaultDataPath        = "/opt/vault/data"
	VaultConfigDirDebian = "/etc/vault.d"
	VaultConfigPath      = "/etc/vault.d/vault.hcl"

	// System
	VaultBinaryPath  = "/usr/bin/vault"
	VaultServicePath = "/etc/systemd/system/vault.service"
)

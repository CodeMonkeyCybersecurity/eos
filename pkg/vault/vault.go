// pkg/vault/vault.go
package vault

var (
	SetupVaultAgent       = setupVaultAgent
	IsAvailable           = isAvailable
	Save                  = save
	Remember              = remember
	VaultPath             = vaultPath
	DiskPath              = diskPath
	Load                  = load
	Read                  = read
	Write                 = write
	HandleFallbackOrStore = handleFallbackOrStore
	ReadStruct            = readStruct
	LoadFromVault         = loadFromVault
	ReadFallbackSecrets   = readFallbackSecrets
	WriteStruct           = writeStruct
)

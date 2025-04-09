// pkg/vault/vault.go
package vault

var (
	SetupVaultAgent       = setupVaultAgent
	Remember              = remember
	VaultPath             = vaultPath
	DiskPath              = diskPath
	Write                 = write
	HandleFallbackOrStore = handleFallbackOrStore
	ReadVaultKV           = readVaultKV
	LoadFromVault         = loadFromVault
	ReadFallbackSecrets   = readFallbackSecrets
	WriteStruct           = writeStruct
	SetVaultEnv           = setVaultEnv
	Purge                 = purge
	WriteFallbackSecrets  = writeFallbackSecrets
	LoadVaultSecureData   = loadVaultSecureData
	PrintNextSteps        = printNextSteps
	Load                  = load
)

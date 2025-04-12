// pkg/vault/vault.go
package vault

var (
	SetupVaultAgent       = setupVaultAgent
	Remember              = remember
	VaultPath             = vaultPath
	DiskPath              = diskPath
	HandleFallbackOrStore = handleFallbackOrStore
	ReadFallbackSecrets   = readFallbackSecrets
	SetVaultEnv           = setVaultEnv
	Purge                 = purge
	WriteFallbackSecrets  = writeFallbackSecrets
	PrintNextSteps        = printNextSteps
)

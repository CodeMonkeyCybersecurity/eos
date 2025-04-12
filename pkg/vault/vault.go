// pkg/vault/vault.go
package vault

var (
	SetupVaultAgent       = setupVaultAgent
	VaultPath             = vaultPath
	DiskPath              = diskPath
	HandleFallbackOrStore = handleFallbackOrStore
	ReadFallbackSecrets   = readFallbackSecrets
	SetVaultEnv           = setVaultEnv
	Purge                 = purge
	PrintNextSteps        = printNextSteps
)

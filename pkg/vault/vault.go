// pkg/vault/vault.go
package vault

var (
	SetupVaultAgent       = setupVaultAgent
	IsAvailable           = isAvailable
	Save                  = save
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
	CheckVaultSecrets     = checkVaultSecrets
	RevokeRootToken       = revokeRootToken
	LoadVaultSecureData   = loadVaultSecureData
	PrintNextSteps        = printNextSteps
	CheckVaultProcesses   = checkVaultProcesses
	Load                  = load
	SaveSecret            = saveSecret
)

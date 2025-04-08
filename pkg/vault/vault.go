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
	ReadVaultJSON         = readVaultJSON
	LoadFromVault         = loadFromVault
	ReadFallbackSecrets   = readFallbackSecrets
	WriteStruct           = writeStruct
	SetVaultEnv           = setVaultEnv
	Purge                 = purge
	WriteFallbackSecrets  = writeFallbackSecrets
	CheckVaultSecrets     = checkVaultSecrets
	RevokeRootToken       = revokeRootToken
	CleanupInitFile       = cleanupInitFile
	LoadVaultSecureData   = loadVaultSecureData
	PrintNextSteps        = printNextSteps
	CheckVaultProcesses   = checkVaultProcesses
)

// pkg/xdg/types.go

package xdg

const (
	// Permission modes (in octal)
	DirPermStandard        = 0755
	VaultRuntimePerms      = 0750
	FilePermOwnerRWX       = 0700
	FilePermStandard       = 0644
	FilePermOwnerReadWrite = 0600
	FilePermReadOnly       = 0444
	OwnerReadOnly          = 0400
)

/* pkg/types/ldap.go */

package types

const (
	LDAPVaultPath        = "eos/ldap"             // For use with WriteToVault, ReadFromVaultAt
	LDAPVaultPathFull    = "secret/data/eos/ldap" // For UI or external calls
	LDAPVaultMount       = "secret"
	LDAPFallbackFileName = "ldap_config.json"
)

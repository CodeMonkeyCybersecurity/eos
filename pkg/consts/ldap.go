/* pkg/consts/ldap.go */

package consts

const (
	LDAPVaultPath        = "eos/ldap"             // For use with WriteToVault, ReadFromVaultAt
	LDAPVaultPathFull    = "secret/data/eos/ldap" // For UI or external calls
	LDAPVaultMount       = "secret"
	LDAPFallbackFileName = "ldap_config.json"
)

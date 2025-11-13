// pkg/shared/vault_entities.go

package shared

const (
	// Vault entity and alias constants
	EosEntityPurpose = "Eos CLI unified identity"
)

type VaultEntity struct {
	Name       string
	Purpose    string
	LookupPath string
	AliasPath  string
	EntityPath string
	PolicyName string
}

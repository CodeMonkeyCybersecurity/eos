// pkg/hpe/types.go

package hpe

// HPEPackage represents an HPE package with its description
type HPEPackage struct {
	Name        string
	Description string
}

// HPEKey represents an HPE GPG public key
type HPEKey struct {
	URL      string
	FileName string
}

// HPERepoConfig holds configuration for HPE repository setup
type HPERepoConfig struct {
	RepoFile     string
	KeyringDir   string
	RepoURL      string
	Keys         []HPEKey
	Packages     []HPEPackage
	Distribution string
}

package remote

// RemoteConfig contains configuration for Git remote operations
// Migrated from cmd/self/git/remote.go package-level variables
type RemoteConfig struct {
	// Common fields
	Path string `json:"path"`

	// List command specific
	OutputJSON bool `json:"output_json"`

	// Add command specific
	AddName string `json:"add_name"`
	AddURL  string `json:"add_url"`

	// Set-URL command specific
	SetURLName string `json:"set_url_name"`
	SetURLURL  string `json:"set_url_url"`

	// Remove command specific
	RemoveName string `json:"remove_name"`

	// Rename command specific
	RenameOldName string `json:"rename_old_name"`
	RenameNewName string `json:"rename_new_name"`
}

/* pkg/delphi/types.go */

package delphi

// DefaultPorts holds the standard Wazuh ports used by the CLI.
var DefaultPorts = []string{
	"443/tcp",
	"1514/tcp",  // Filebeat/agent TCP
	"1515/tcp",  // Agent registration
	"55000/tcp", // API
}

// User represents a Wazuh API user object
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
}

const (
	APICreds = "eos/delphi/api_creds"
)

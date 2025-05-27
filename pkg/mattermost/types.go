// pkg/mattermost/types.go

package mattermost

// DirNames lists the required subdirectories for Mattermost volumes.
var DirNames = []string{
	"config", "data", "logs", "plugins", "client/plugins", "bleve-indexes",
}

// DefaultEnvUpdates holds the standard .env key/value overrides
// for our internal Mattermost deployment.
var DefaultEnvUpdates = map[string]string{
	"DOMAIN":                          "localhost",
	"PORT":                            "8017",
	"MM_SUPPORTSETTINGS_SUPPORTEMAIL": "support@cybermonkey.net.au",
}

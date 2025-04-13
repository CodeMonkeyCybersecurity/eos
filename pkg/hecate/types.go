/* pkg/hecate/types.go */

package hecate

import (
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/types"
)

// Constants for file locations.
// Constant file and directory names.
const (
	LastValuesFile    = ".hecate.conf"
	ConfDir           = "conf.d"
	DockerComposeFile = "docker-compose.yml"
	DstConf           = "conf.d"
	DstCerts          = "certs"
	DstCompose        = "docker-compose.yml"
)

const (
	SRC_CONF       = "conf.d"
	SRC_CERTS      = "certs"
	SRC_COMPOSE    = "docker-compose.yml"
	BACKUP_CONF    = "conf.d.bak"
	BACKUP_CERTS   = "certs.bak"
	BACKUP_COMPOSE = "docker-compose.yml.bak"
)

// Dynamic values computed at runtime.
var (
	Timestamp     = time.Now().Format("20060102-150405")
	BackupConf    = types.DefaultConfDir + "." + Timestamp + ".bak"
	BackupCerts   = types.DefaultCertsDir + "." + Timestamp + ".bak"
	BackupCompose = types.DefaultComposeYML + "." + Timestamp + ".bak"
)

// AppSelection holds an app name and its configuration file.
type AppSelection struct {
	AppName  string
	ConfFile string
}

// Global mapping from option number to its corresponding AppSelection.
var AppsSelection = map[string]AppSelection{
	"1":  {"Static website", "base.conf"},
	"2":  {"Wazuh", "delphi.conf"},
	"3":  {"Mattermost", "collaborate.conf"},
	"4":  {"Nextcloud", "cloud.conf"},
	"5":  {"Mailcow", "mailcow.conf"},
	"6":  {"Jenkins", "jenkins.conf"},
	"7":  {"Grafana", "observe.conf"},
	"8":  {"Umami", "analytics.conf"},
	"9":  {"MinIO", "s3.conf"},
	"10": {"Wiki.js", "wiki.conf"},
	"11": {"ERPNext", "erp.conf"},
	"12": {"Jellyfin", "jellyfin.conf"},
	"13": {"Persephone", "persephone.conf"},
}

// supportedApps maps the app’s lowercase name to a list of port markers.
var SupportedApps = map[string][]string{
	"wazuh":     {"1515", "1514", "55000"},
	"mailcow":   {"25", "587", "465", "110", "995", "143", "993"},
	"nextcloud": {"3478"},
}

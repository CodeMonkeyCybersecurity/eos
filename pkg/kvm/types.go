// pkg/kvm/types.go

package kvm

type CloudInitConfig struct {
	VMName     string
	CloudImg   string // e.g. /srv/iso/ubuntu-22.04-server-cloudimg-amd64.img
	PublicKey  string // path to .pub file or literal key string
	DiskSizeGB int    // e.g. 20
	UseUEFI    bool   // default: true
}

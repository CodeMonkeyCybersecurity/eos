package consul

// TemplateData holds the data needed for Terraform template generation
type TemplateData struct {
	VaultAddr        string
	ConsulDatacenter string
	ClusterName      string
	ServerCount      int
	ClientCount      int
	ServerType       string
	Location         string
	SSHKeyName       string
}

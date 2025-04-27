// pkg/shared/vault_templates.go

package shared

// Vault Agent configuration template used to render agent config file at runtime.
const AgentConfigTmpl = `
vault {
  address     = "{{ .Addr }}"
  tls_ca_file = "{{ .CACert }}"
}
#listener "tcp" {
#  address = "127.0.0.1:"
#}
auto_auth {
  method "approle" {
    config = {
      role_id_file_path   = "{{ .RoleFile }}"
      secret_id_file_path = "{{ .SecretFile }}"
    }
  }
  sink "file" { config = { path = "{{ .TokenSink }}" } }
}
#cache { use_auto_auth_token = true }
`

// AgentSystemDUnit is the systemd unit template for running Vault Agent under eos.
const AgentSystemDUnit = `
[Unit]
Description=Vault Agent (Eos)
After=network.target

[Service]
Environment=HCP_VAULT_SKIP_AUTO_PROVISION=1
User=%s
Group=%s
# make /run/eos for the runtime directory
RuntimeDirectory=eos
RuntimeDirectoryMode=%o
ExecStartPre=/usr/bin/install -d -o %s -g %s -m%o %s
ExecStart=/usr/bin/vault agent -config=%s
Restart=on-failure

[Install]
WantedBy=multi-user.target
`

// Vault Server systemd unit template (vault.service)
const ServerSystemDUnit = `
[Unit]
Description=Vault Server (Eos)
After=network.target

[Service]
User=eos
Group=eos
ExecStart=/usr/bin/vault server -config=/etc/vault.d/vault.hcl
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`

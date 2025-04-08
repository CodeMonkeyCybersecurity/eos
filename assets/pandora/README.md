# Pandora

Clean, production-ready folder structure using ASCII tree layout for your Vault + Agent + NGINX stack, including systemd compatibility:

⸻

## 📁 pandora/ directory layout
```
/opt/eos/compose/vault
├── docker-compose.production.yaml     # Main compose file (Vault, Agent, NGINX)
├── config/
│   └── vault.hcl                      # Vault config using Raft backend
├── agent/
│   ├── vault-agent.hcl                # Vault Agent config (token sink)
│   └── vault-agent.pass               # EOS user password (600 perms)
├── nginx/
│   ├── nginx.conf                     # Reverse proxy config
│   └── ssl/
│       ├── vault.crt                  # Self-signed cert for HTTPS
│       └── vault.key                  # Private key
└── systemd/
    └── vault-stack.service            # Optional systemd unit for autostart
```


⸻

# 🛠️ Summary of Each Component

## File/Folder	Purpose
docker-compose.production.yaml	Defines Vault, Vault Agent, and NGINX services
config/vault.hcl	Vault config with Raft backend and TCP listener
agent/vault-agent.hcl	Configures auto-auth with userpass and token sink
agent/vault-agent.pass	Vault user password for auto-auth
nginx/nginx.conf	Secures access to Vault with reverse proxy + TLS
nginx/ssl/	Local CA cert + key for HTTPS (self-signed or real cert)
systemd/vault-stack.service	Enables auto-start of your full Vault stack at boot


# Environment Variables

Reference for runtime environment variables used by Eos and the underlying stack. Confirm values against service implementations before relying on them in automation.

## Core (Eos CLI)
- `EOS_CONFIG` — optional path override for configuration files (when supported by the command).
- `EOS_LOG_LEVEL` — desired log level (info/debug/warn). Align with telemetry settings.
- `NO_COLOR` — disable colorized output when scripting.

## HashiCorp stack
- `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_NAMESPACE` — Vault access.
- `CONSUL_HTTP_ADDR`, `CONSUL_HTTP_TOKEN` — Consul access.
- `NOMAD_ADDR`, `NOMAD_TOKEN` — Nomad access.

## Platform and networking
- `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` — proxy configuration for outbound requests.
- `KUBECONFIG` — kubeconfig path when interacting with K3s or other clusters.

## Security and access
- `SSH_AUTH_SOCK` — SSH agent socket for key forwarding to bastions.
- `AWS_PROFILE` / cloud-provider-specific credentials — when provisioning cloud-backed resources (document per service).

## Contributor notes
- Keep this list in sync with code; remove vars that are not honored and add flags/env overrides as they are implemented.
- Document precedence with configuration files and CLI flags in [configuration.md](configuration.md).

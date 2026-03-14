---
description: Eos secrets and Vault/Consul patterns — storage, delivery, cluster auth
paths:
  - "pkg/vault/**"
  - "pkg/consul/**"
  - "pkg/secrets/**"
  - "cmd/create/**"
  - "cmd/update/**"
---

# Secrets and Vault/Consul Patterns

## Storage Decision

| Data type | Storage | Delivery |
|---|---|---|
| Passwords, API keys, tokens, TLS keys | Vault KV (`secret/[service]/[key]`) | Vault Agent template |
| Feature flags, ports, URLs, log levels | Consul KV (`service/[service]/config/[key]`) | Consul Template or direct read |
| Both secrets + config | Vault + Consul | Consul Template (both backends) |

**Never**: hardcode credentials, store secrets in env files, or use `.env` without Vault Agent rendering.

## Secret Storage Pattern

```go
// At service installation time
secretManager, err := secrets.NewSecretManager(rc, envConfig)
requiredSecrets := map[string]secrets.SecretType{
    "db_password": secrets.SecretTypePassword,
    "api_key":     secrets.SecretTypeAPIKey,
    "jwt_secret":  secrets.SecretTypeToken,
}
serviceSecrets, err := secretManager.GetOrGenerateServiceSecrets("myservice", requiredSecrets)
// Stored at: secret/myservice/{db_password,api_key,jwt_secret}
```

**Path convention**: `secret/[service-name]/[secret-key]`

## Vault Cluster Authentication (P1 — Critical)

### Authentication Hierarchy

Eos uses a priority-based token resolution chain:

1. **Explicit CLI token** — `--token` flag (highest priority)
2. **VAULT_TOKEN env var** — operator-set environment variable
3. **Interactive prompt** — TTY-available fallback with help text
4. **Vault Agent token** — file at `/run/eos/vault_agent_eos.token`
5. **AppRole** — programmatic auth with Role ID + Secret ID
6. **Error with remediation** — non-interactive mode, clear steps (lowest priority)

Use `interaction.GetRequiredString()` for the CLI fallback chain (see cli-patterns.md).

### Token Validation Sequence

Before using a Vault token, validate:
1. Check token is non-empty
2. Verify token format (starts with `s.` or `hvs.`)
3. Call `/v1/auth/token/lookup-self` to verify it's not expired
4. Check token policies include required capabilities
5. Log token source and expiry for observability

### Token Security

```go
// NEVER log full token — log only last 4 chars
logger.Info("Using Vault token", zap.String("token_suffix", token[len(token)-4:]))

// NEVER store token in environment variable after lookup
// Use the file-based token from Vault Agent: /run/eos/vault_agent_eos.token

// NEVER expose token in error messages
return fmt.Errorf("vault auth failed — token invalid or expired")  // no token value
```

### Common Vault Auth Pitfalls

| Pitfall | What happens | Fix |
|---|---|---|
| Token passed in URL query param | Token in server logs | Use Authorization header |
| Token stored in VAULT_TOKEN env | Visible via `/proc/<pid>/environ` | Use temp file, delete after use |
| Not checking token expiry | Silent auth failure mid-operation | Validate with lookup-self before use |
| AppRole Secret ID reuse | Rotation breaks silently | Use `SecretIDNumUses=1` or short TTL |

## Vault Agent Template (Secrets Only)

Use when: service only needs Vault secrets, no dynamic Consul config.

```hcl
# /etc/vault.d/templates/myservice.env.ctmpl
DATABASE_PASSWORD={{ with secret "secret/myservice/db_password" }}{{ .Data.data.value }}{{ end }}
API_KEY={{ with secret "secret/myservice/api_key" }}{{ .Data.data.value }}{{ end }}
```

```hcl
# In vault agent config
template {
  source      = "/etc/vault.d/templates/myservice.env.ctmpl"
  destination = "/opt/myservice/.env"
  perms       = "0640"
  command     = "docker compose -f /opt/myservice/docker-compose.yml up -d --force-recreate"
}
```

## Consul Template (Secrets + Config)

Use when: service needs both Vault secrets AND dynamic Consul config.

```hcl
# /etc/consul-template.d/myservice.env.ctmpl
PORT={{ key "service/myservice/config/port" }}
ENABLE_RAG={{ key "service/myservice/config/feature_flags/enable_rag" }}
DATABASE_PASSWORD={{ with secret "secret/myservice/db_password" }}{{ .Data.data.value }}{{ end }}
```

Reuse the Vault Agent token: `{{ file "/run/eos/vault_agent_eos.token" }}`

## Docker Operations (P1 — Critical)

Container operations: ALWAYS use Docker SDK (`github.com/docker/docker/client`), NOT shell exec.

Docker Compose validation: use `docker.ValidateComposeWithShellFallback(ctx, composeFile, envFile)`:
- Strategy: SDK first (35μs), shell fallback (`docker compose config`) if SDK fails
- NEVER run `docker compose up` without validation first

Template rendering: use `pkg/templates/render.go` — NEVER `template.New()` scattered in packages.

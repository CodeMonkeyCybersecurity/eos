// pkg/apiclient/auth.go
// Credential discovery for API authentication
//
// PRIORITY ORDER (AUTHORITATIVE - next 6 months):
//   1. .env file (primary for next 6 months)
//   2. Consul KV (preferred long-term)
//   3. Vault (secure, rotatable)
//   4. Environment variable (runtime override)
//   5. Interactive prompt (human-centric fallback)
//   6. Error with remediation (actionable guidance)
//
// RATIONALE: .env files provide simplest onboarding for new users
// MIGRATION PATH: After 6 months, shift to Consul KV as primary

package apiclient

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Credential Discovery (with .env priority)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// DiscoverAuthToken discovers API authentication token using fallback chain
// PRIORITY ORDER (.env first for next 6 months):
//  1. .env file (if auth.token_env_file + auth.token_env_var set)
//  2. Consul KV (if auth.token_consul_key set)
//  3. Vault (if auth.token_vault_path set)
//  4. Environment variable (if auth.token_env_var set)
//  5. Interactive prompt (if TTY available)
//  6. Error with remediation (if non-interactive)
//
// Parameters:
//   - rc: RuntimeContext for logging, secrets access
//   - auth: AuthConfig from API definition
//   - service: Service name (for error messages, prompts)
//
// Returns: (token string, source string, error)
//
// Example:
//
//	token, source, err := DiscoverAuthToken(rc, def.Auth, "authentik")
//	if err != nil {
//	    return fmt.Errorf("failed to discover auth token: %w", err)
//	}
//	logger.Info("Using auth token", zap.String("source", source))
func DiscoverAuthToken(rc *eos_io.RuntimeContext, auth AuthConfig, service string) (string, string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// PRIORITY 1: .env file (primary for next 6 months)
	if auth.TokenEnvFile != "" && auth.TokenEnvVar != "" {
		// P1 SECURITY FIX: Check .env file permissions before reading
		// RATIONALE: World/group-readable .env exposes tokens to unauthorized users
		// THREAT MODEL: Local privilege escalation (low-priv user reads admin token)
		if info, statErr := os.Stat(auth.TokenEnvFile); statErr == nil {
			perm := info.Mode().Perm()
			// Check if world-readable (0004) or group-readable (0040)
			if perm&0044 != 0 {
				logger.Warn("SECURITY: .env file has insecure permissions (world/group readable)",
					zap.String("file", auth.TokenEnvFile),
					zap.String("current_perms", fmt.Sprintf("%04o", perm)),
					zap.String("recommended_perms", "0600"),
					zap.String("fix_command", fmt.Sprintf("chmod 0600 %s", auth.TokenEnvFile)),
					zap.String("threat", "Tokens may be readable by unauthorized users"))
			}
		}

		token, found, err := shared.GetEnvVar(auth.TokenEnvFile, auth.TokenEnvVar)
		if err == nil && found && token != "" {
			logger.Info("Using auth token from .env file",
				zap.String("service", service),
				zap.String("file", auth.TokenEnvFile),
				zap.String("var", auth.TokenEnvVar),
				zap.String("source", ".env file"))
			return token, ".env file", nil
		}
		if err != nil {
			logger.Debug(".env file not accessible",
				zap.String("file", auth.TokenEnvFile),
				zap.Error(err))
		}
	}

	// PRIORITY 2: Consul KV (preferred long-term)
	if auth.TokenConsulKey != "" {
		// TODO: Implement Consul KV lookup
		// token, err := consulClient.KV().Get(auth.TokenConsulKey, nil)
		// if err == nil && token != nil && string(token.Value) != "" {
		//     logger.Info("Using auth token from Consul KV",
		//         zap.String("service", service),
		//         zap.String("key", auth.TokenConsulKey),
		//         zap.String("source", "Consul KV"))
		//     return string(token.Value), "Consul KV", nil
		// }
		logger.Debug("Consul KV lookup not yet implemented",
			zap.String("key", auth.TokenConsulKey))
	}

	// PRIORITY 3: Vault (secure, rotatable)
	if auth.TokenVaultPath != "" {
		// TODO: Implement Vault lookup
		// secret, err := vaultClient.Logical().Read(auth.TokenVaultPath)
		// if err == nil && secret != nil {
		//     if tokenValue, ok := secret.Data["value"].(string); ok && tokenValue != "" {
		//         logger.Info("Using auth token from Vault",
		//             zap.String("service", service),
		//             zap.String("path", auth.TokenVaultPath),
		//             zap.String("source", "Vault"))
		//         return tokenValue, "Vault", nil
		//     }
		// }
		logger.Debug("Vault lookup not yet implemented",
			zap.String("path", auth.TokenVaultPath))
	}

	// PRIORITY 4: Environment variable (runtime override)
	if auth.TokenEnvVar != "" {
		token := os.Getenv(auth.TokenEnvVar)
		if token != "" {
			logger.Info("Using auth token from environment variable",
				zap.String("service", service),
				zap.String("var", auth.TokenEnvVar),
				zap.String("source", "environment variable"))
			return token, "environment variable", nil
		}
	}

	// PRIORITY 5: Interactive prompt (human-centric fallback)
	if interaction.IsTTY() {
		logger.Info("No auth token found, prompting user",
			zap.String("service", service))

		result, err := interaction.GetRequiredString(rc, "", false, &interaction.RequiredFlagConfig{
			FlagName:      "token",
			PromptMessage: fmt.Sprintf("Enter %s API token: ", service),
			HelpText: fmt.Sprintf("API token for %s authentication.\n"+
				"Get token from service admin panel.\n"+
				"Store in .env file for persistence:\n"+
				"  echo '%s=your_token_here' >> %s",
				service, auth.TokenEnvVar, auth.TokenEnvFile),
			IsSecret: true,
		})
		if err != nil {
			return "", "", fmt.Errorf("failed to prompt for token: %w", err)
		}

		logger.Info("Using auth token from interactive prompt",
			zap.String("service", service),
			zap.String("source", "interactive prompt"))
		return result.Value, "interactive prompt", nil
	}

	// PRIORITY 6: Error with remediation (non-interactive mode)
	return "", "", buildTokenNotFoundError(service, auth)
}

// DiscoverBaseURL discovers API base URL using fallback chain
// PRIORITY ORDER (same as token):
//  1. .env file (if auth.base_url_env_file + auth.base_url_env_var set)
//  2. Consul KV (if auth.base_url_consul_key set)
//  3. Direct URL (if def.BaseURL set in YAML)
//  4. Environment variable (if auth.base_url_env_var set)
//  5. Interactive prompt (if TTY available)
//  6. Error with remediation (if non-interactive)
//
// Example:
//
//	baseURL, source, err := DiscoverBaseURL(rc, def.Auth, def.BaseURL, "authentik")
func DiscoverBaseURL(rc *eos_io.RuntimeContext, auth AuthConfig, directURL, service string) (string, string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// PRIORITY 1: .env file (primary for next 6 months)
	if auth.BaseURLEnvFile != "" && auth.BaseURLEnvVar != "" {
		url, found, err := shared.GetEnvVar(auth.BaseURLEnvFile, auth.BaseURLEnvVar)
		if err == nil && found && url != "" {
			logger.Info("Using base URL from .env file",
				zap.String("service", service),
				zap.String("file", auth.BaseURLEnvFile),
				zap.String("var", auth.BaseURLEnvVar),
				zap.String("url", url))
			return url, ".env file", nil
		}
	}

	// PRIORITY 2: Consul KV (preferred long-term)
	if auth.BaseURLConsulKey != "" {
		// TODO: Implement Consul KV lookup
		logger.Debug("Consul KV lookup not yet implemented",
			zap.String("key", auth.BaseURLConsulKey))
	}

	// PRIORITY 3: Direct URL (from YAML definition)
	if directURL != "" {
		logger.Info("Using base URL from API definition",
			zap.String("service", service),
			zap.String("url", directURL))
		return directURL, "API definition", nil
	}

	// PRIORITY 4: Environment variable (runtime override)
	if auth.BaseURLEnvVar != "" {
		url := os.Getenv(auth.BaseURLEnvVar)
		if url != "" {
			logger.Info("Using base URL from environment variable",
				zap.String("service", service),
				zap.String("var", auth.BaseURLEnvVar),
				zap.String("url", url))
			return url, "environment variable", nil
		}
	}

	// PRIORITY 5: Interactive prompt (human-centric fallback)
	if interaction.IsTTY() {
		logger.Info("No base URL found, prompting user",
			zap.String("service", service))

		result, err := interaction.GetRequiredString(rc, "", false, &interaction.RequiredFlagConfig{
			FlagName:      "url",
			PromptMessage: fmt.Sprintf("Enter %s API base URL: ", service),
			HelpText: fmt.Sprintf("Base URL for %s API (e.g., https://auth.example.com).\n"+
				"Store in .env file for persistence:\n"+
				"  echo '%s=https://your-url-here' >> %s",
				service, auth.BaseURLEnvVar, auth.BaseURLEnvFile),
			IsSecret: false,
		})
		if err != nil {
			return "", "", fmt.Errorf("failed to prompt for base URL: %w", err)
		}

		return result.Value, "interactive prompt", nil
	}

	// PRIORITY 6: Error with remediation
	return "", "", buildBaseURLNotFoundError(service, auth)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Error Messages (with remediation steps)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// buildTokenNotFoundError builds actionable error message for missing token
func buildTokenNotFoundError(service string, auth AuthConfig) error {
	msg := fmt.Sprintf("API token not found for %s.\n\n", service)
	msg += "Try one of the following (in priority order):\n\n"

	// Option 1: .env file (PRIMARY)
	if auth.TokenEnvFile != "" && auth.TokenEnvVar != "" {
		msg += fmt.Sprintf("1. [RECOMMENDED] Add to .env file:\n")
		msg += fmt.Sprintf("   echo '%s=your_token_here' >> %s\n\n", auth.TokenEnvVar, auth.TokenEnvFile)
	}

	// Option 2: Consul KV
	if auth.TokenConsulKey != "" {
		msg += fmt.Sprintf("2. Store in Consul KV:\n")
		msg += fmt.Sprintf("   consul kv put %s your_token_here\n\n", auth.TokenConsulKey)
	}

	// Option 3: Vault
	if auth.TokenVaultPath != "" {
		msg += fmt.Sprintf("3. Store in Vault:\n")
		msg += fmt.Sprintf("   vault kv put %s value=your_token_here\n\n", auth.TokenVaultPath)
	}

	// Option 4: Environment variable
	if auth.TokenEnvVar != "" {
		msg += fmt.Sprintf("4. Set environment variable:\n")
		msg += fmt.Sprintf("   export %s=your_token_here\n\n", auth.TokenEnvVar)
	}

	msg += "5. Run interactively (will prompt for token):\n"
	msg += fmt.Sprintf("   eos <command> (without --non-interactive flag)\n")

	return fmt.Errorf(msg)
}

// buildBaseURLNotFoundError builds actionable error message for missing base URL
func buildBaseURLNotFoundError(service string, auth AuthConfig) error {
	msg := fmt.Sprintf("API base URL not found for %s.\n\n", service)
	msg += "Try one of the following (in priority order):\n\n"

	// Option 1: .env file (PRIMARY)
	if auth.BaseURLEnvFile != "" && auth.BaseURLEnvVar != "" {
		msg += fmt.Sprintf("1. [RECOMMENDED] Add to .env file:\n")
		msg += fmt.Sprintf("   echo '%s=https://your-url-here' >> %s\n\n", auth.BaseURLEnvVar, auth.BaseURLEnvFile)
	}

	// Option 2: Consul KV
	if auth.BaseURLConsulKey != "" {
		msg += fmt.Sprintf("2. Store in Consul KV:\n")
		msg += fmt.Sprintf("   consul kv put %s https://your-url-here\n\n", auth.BaseURLConsulKey)
	}

	// Option 3: Environment variable
	if auth.BaseURLEnvVar != "" {
		msg += fmt.Sprintf("3. Set environment variable:\n")
		msg += fmt.Sprintf("   export %s=https://your-url-here\n\n", auth.BaseURLEnvVar)
	}

	msg += "4. Run interactively (will prompt for URL):\n"
	msg += fmt.Sprintf("   eos <command> (without --non-interactive flag)\n")

	return fmt.Errorf(msg)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// .env File Helpers (convenience wrappers)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// StoreTokenInEnvFile stores API token in .env file (idempotent)
// SECURITY: Uses 0600 permissions (owner read/write only)
//
// Example:
//
//	err := StoreTokenInEnvFile("/opt/hecate/.env", "AUTHENTIK_TOKEN", token)
func StoreTokenInEnvFile(envFile, varName, token string) error {
	return shared.UpdateEnvVar(envFile, varName, token, 0600)
}

// StoreBaseURLInEnvFile stores API base URL in .env file (idempotent)
// SECURITY: Uses 0644 permissions (not secret, but user-owned)
//
// Example:
//
//	err := StoreBaseURLInEnvFile("/opt/hecate/.env", "AUTHENTIK_URL", "https://auth.example.com")
func StoreBaseURLInEnvFile(envFile, varName, url string) error {
	return shared.UpdateEnvVar(envFile, varName, url, 0600)
}

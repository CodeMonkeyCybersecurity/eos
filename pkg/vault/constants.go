// pkg/vault/constants.go

package vault

import (
	"fmt"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

const (
	EnvVaultAddress          = "VAULT_ADDR"
	EnvVaultAgentAddr        = "VAULT_AGENT_ADDR"
	EnvVaultCACert           = "VAULT_CACERT"
	EnvVaultCACertBytes      = "VAULT_CACERT_BYTES"
	EnvVaultCAPath           = "VAULT_CAPATH"
	EnvVaultClientCert       = "VAULT_CLIENT_CERT"
	EnvVaultClientKey        = "VAULT_CLIENT_KEY"
	EnvVaultClientTimeout    = "VAULT_CLIENT_TIMEOUT"
	EnvVaultHeaders          = "VAULT_HEADERS"
	EnvVaultSRVLookup        = "VAULT_SRV_LOOKUP"
	EnvVaultSkipVerify       = "VAULT_SKIP_VERIFY"
	EnvVaultNamespace        = "VAULT_NAMESPACE"
	EnvVaultTLSServerName    = "VAULT_TLS_SERVER_NAME"
	EnvVaultWrapTTL          = "VAULT_WRAP_TTL"
	EnvVaultMaxRetries       = "VAULT_MAX_RETRIES"
	EnvVaultToken            = "VAULT_TOKEN"
	EnvVaultMFA              = "VAULT_MFA"
	EnvRateLimit             = "VAULT_RATE_LIMIT"
	EnvHTTPProxy             = "VAULT_HTTP_PROXY"
	EnvVaultProxyAddr        = "VAULT_PROXY_ADDR"
	EnvVaultDisableRedirects = "VAULT_DISABLE_REDIRECTS"
	HeaderIndex              = "X-Vault-Index"
	HeaderForward            = "X-Vault-Forward"
	HeaderInconsistent       = "X-Vault-Inconsistent"

	// NamespaceHeaderName is the header set to specify which namespace the
	// request is indented for.
	NamespaceHeaderName = "X-Vault-Namespace"

	// AuthHeaderName is the name of the header containing the token.
	AuthHeaderName = "X-Vault-Token"

	// RequestHeaderName is the name of the header used by the Agent for
	// SSRF protection.
	RequestHeaderName = "X-Vault-Request"

	TLSErrorString = "This error usually means that the server is running with TLS disabled\n" +
		"but the client is configured to use TLS. Please either enable TLS\n" +
		"on the server or run the client with -address set to an address\n" +
		"that uses the http protocol:\n\n" +
		"    vault <command> -address http://<address>\n\n" +
		"You can also set the VAULT_ADDR environment variable:\n\n\n" +
		"    VAULT_ADDR=http://<address> vault <command>\n\n" +
		"where <address> is replaced by the actual address to the server."
)

const (
	EnvVaultAgentAddress = "VAULT_AGENT_ADDR"
	EnvVaultInsecure     = "VAULT_SKIP_VERIFY"
)

var (
	DefaultAddress = fmt.Sprintf("https://127.0.0.1:%d", shared.PortVault)
)

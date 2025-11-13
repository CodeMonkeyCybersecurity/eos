// pkg/vault/variables.go

package vault

import (
	"net/http"
	"os"

	cerr "github.com/cockroachdb/errors"
)

var (
	ErrLifetimeWatcherMissingInput  = cerr.New("missing input")
	ErrLifetimeWatcherMissingSecret = cerr.New("missing secret")
	ErrLifetimeWatcherNotRenewable  = cerr.New("secret is not renewable")
	ErrLifetimeWatcherNoSecretData  = cerr.New("returned empty secret data")

	// DefaultLifetimeWatcherRenewBuffer is the default size of the buffer for renew
	// messages on the channel.
	DefaultLifetimeWatcherRenewBuffer = 5
	// Deprecated: kept for backwards compatibility
	DefaultRenewerRenewBuffer = 5
)

var (
	// The default TTL that will be used with `sys/wrapping/wrap`, can be
	// changed
	DefaultWrappingTTL = "5m"

	// The default function used if no other function is set. It honors the env
	// var to set the wrap TTL. The default wrap TTL will apply when when writing
	// to `sys/wrapping/wrap` when the env var is not set.
	DefaultWrappingLookupFunc = func(operation, path string) string {
		if os.Getenv(EnvVaultWrapTTL) != "" {
			return os.Getenv(EnvVaultWrapTTL)
		}

		if (operation == http.MethodPut || operation == http.MethodPost) && path == "sys/wrapping/wrap" {
			return DefaultWrappingTTL
		}

		return ""
	}
)

var ErrIncompleteSnapshot = cerr.New("incomplete snapshot, unable to read SHA256SUMS.sealed file")

// Use the one defined in types.go instead
// var ErrSecretNotFound = cerr.New("secret not found")

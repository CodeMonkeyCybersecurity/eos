/* pkg/eoscli/eoscli.go
 */

package eoscli

// Public exports from eoscli helpers
var (
	Wrap                   = wrap                // from context.go
	EnsureEOSSystemUser    = ensureEOSSystemUser // from check.go
	PrintBanner            = printBanner         // from print.go
	PrintJSON              = printJSON           // from print.go
	EnableVaultAuthMethods = enableVaultAuthMethods
)

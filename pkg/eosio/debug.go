// pkg/eosio/debug.go
package eosio

var DebugMode bool

func SetDebugMode(enabled bool) {
	DebugMode = enabled
}

func DebugEnabled() bool {
	return DebugMode
}

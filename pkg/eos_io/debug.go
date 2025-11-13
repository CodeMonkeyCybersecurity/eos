// pkg/eos_io/debug.go
package eos_io

var DebugMode bool

func SetDebugMode(enabled bool) {
	DebugMode = enabled
}

func DebugEnabled() bool {
	return DebugMode
}

// pkg/eos_io/types.go

package eos_io

// contextKey is an unexported type used for safely storing RuntimeContext in context.Context.
type contextKey struct {
	name string
}

// RuntimeContextKey is the key used in cobra.Command.Context() to retrieve our RuntimeContext.
// Should be unique and stable.
var RuntimeContextKey = &contextKey{"eos-runtime-context"}

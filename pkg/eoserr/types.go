// pkg/eoserr/types.go

package eoserr

import "errors"

var ErrFallbackUsed = errors.New("fallback logger used")

// ErrReexecCompleted is returned when the process successfully re-executes as eos user.
var ErrReexecCompleted = errors.New("eos reexec completed")

// Optional: you can predefine a standard error for special cases
var ErrSecretNotFound = errors.New("vault secret not found")

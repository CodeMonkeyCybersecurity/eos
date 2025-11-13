// pkg/eos_err/wrap.go

package eos_err

import (
	cerr "github.com/cockroachdb/errors"
)

func WrapValidationError(err error) error {
	return cerr.WithHint(cerr.WithStack(err), "validation failed")
}

func WrapPolicyError(err error) error {
	return cerr.WithHint(cerr.WithStack(err), "OPA policy enforcement failed")
}

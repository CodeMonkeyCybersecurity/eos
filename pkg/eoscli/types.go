// pkg/eoscli/types.go

package eoscli

import (
	cerr "github.com/cockroachdb/errors"
)

type WrapValidation struct {
	Cfg         any
	SchemaPath  string
	YAMLPath    string
	PolicyPath  string
	PolicyInput func() any
}

var errStackedMarker = cerr.New("stack already attached")

// pkg/eos_cli/types.go

package eos_cli

type WrapValidation struct {
	Cfg         any
	SchemaPath  string
	YAMLPath    string
	PolicyPath  string
	PolicyInput func() any
}

var (
	nonInteractive bool
	orphansOnly    bool
	kernelsOnly    bool
)

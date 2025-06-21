// pkg/verify/types.go

package verify

import "cuelang.org/go/cue/cuecontext"

// cueCtx is unused but kept for potential future CUE validation functionality
var _ = cuecontext.New()

type Context struct {
	Cfg         any
	SchemaPath  string
	YAMLPath    string
	PolicyPath  string
	PolicyInput func() any
}

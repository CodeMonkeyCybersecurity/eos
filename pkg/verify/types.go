// pkg/verify/types.go

package verify

import "cuelang.org/go/cue/cuecontext"

var cueCtx = cuecontext.New()

type Context struct {
	Cfg         any
	SchemaPath  string
	YAMLPath    string
	PolicyPath  string
	PolicyInput func() any
}

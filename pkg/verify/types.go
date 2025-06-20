// pkg/verify/types.go

package verify

type Context struct {
	Cfg         any
	SchemaPath  string
	YAMLPath    string
	PolicyPath  string
	PolicyInput func() any
}

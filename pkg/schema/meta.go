// pkg/schema/meta.go
package schema

type FieldMeta struct {
	Label     string // e.g. "BindDN"
	Help      string // e.g. "The distinguished name for binding to the server"
	Required  bool   // Is this field required for a successful config?
	Sensitive bool   // Should input be hidden (passwords)?
}

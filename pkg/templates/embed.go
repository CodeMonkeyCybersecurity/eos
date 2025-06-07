// pkg/templates/embed.go
package templates

import (
	"embed"
)

//go:embed *.txt *.html
var FS embed.FS

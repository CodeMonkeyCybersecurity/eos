// pkg/ollama/types.go

package ollama

type WebUIConfig struct {
	Container string `validate:"required,hostname"`
	Port      int    `validate:"required,min=1,max=65535"`
	Volume    string `validate:"required"`
}

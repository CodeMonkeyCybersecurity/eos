// pkg/verify/validator.go

package verify

import (
	"fmt"
	"strings"

	"github.com/go-playground/validator/v10"
	"go.uber.org/zap"
)

var validate = validator.New()

func Struct(v interface{}) error {
	return validate.Struct(v)
}

func MustValid(v interface{}) {
	if err := validate.Struct(v); err != nil {
		zap.L().Fatal("🚫 Invalid input", zap.Error(err))
	}
}

func DescribeValidation(err error) string {
	if ve, ok := err.(validator.ValidationErrors); ok {
		var parts []string
		for _, field := range ve {
			parts = append(parts, fmt.Sprintf("%s=%s", field.Field(), field.Tag()))
		}
		return strings.Join(parts, ", ")
	}
	return err.Error()
}

func ValidateStructWithGoPlayground(obj interface{}) error {
	return validate.Struct(obj)
}

type WrapValidation struct {
	Cfg         any
	SchemaPath  string
	YAMLPath    string
	PolicyPath  string
	PolicyInput func() any
	ServiceName string // optional — for telemetry
}

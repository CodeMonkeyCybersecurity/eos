// pkg/eos_cue/cue.go

package eos_cue

import (
	"context"
	"fmt"
	"os"

	"cuelang.org/go/cue/cuecontext"
	"cuelang.org/go/cue/load"
	"cuelang.org/go/encoding/yaml"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_opa"
	"github.com/go-playground/validator/v10"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// One global CUE context is fine for pure validation.
var cueCtx = cuecontext.New()

// Struct validates a Go struct with `validate:` tags (playground/validator).
// You can rename or extend this as you like.
func Struct(v any) error {
	return validator.New().Struct(v)
}

func ValidateYAMLWithCUE(schemaPath, yamlPath string) error {
	schemaInst := load.Instances([]string{schemaPath}, nil)
	if len(schemaInst) == 0 || schemaInst[0].Err != nil {
		return fmt.Errorf("load cue schema: %w", schemaInst[0].Err)
	}
	schema := cueCtx.BuildInstance(schemaInst[0])
	if schema.Err() != nil {
		return fmt.Errorf("build cue schema: %w", schema.Err())
	}

	yamlData, err := os.ReadFile(yamlPath)
	if err != nil {
		return fmt.Errorf("read yaml: %w", err)
	}
	file, err := yaml.Extract("", yamlData)
	if err != nil {
		return fmt.Errorf("parse yaml: %w", err)
	}
	input := cueCtx.BuildFile(file)
	if input.Err() != nil {
		return fmt.Errorf("build cue from yaml: %w", input.Err())
	}

	if err := schema.Unify(input).Validate(); err != nil {
		return fmt.Errorf("cue validation failed: %w", err)
	}
	return nil
}

func VerifyAll(ctx context.Context, cfg any, schemaPath, yamlPath, policyPath string, policyInput any) error {
	if err := Struct(cfg); err != nil {
		otelzap.Ctx(ctx).Error("Struct validation failed", zap.Error(err))
		return fmt.Errorf("struct validation failed: %w", err)
	}

	if err := ValidateYAMLWithCUE(schemaPath, yamlPath); err != nil {
		otelzap.Ctx(ctx).Error("CUE validation failed", zap.String("schema", schemaPath), zap.Error(err))
		return fmt.Errorf("cue validation failed: %w", err)
	}

	denies, err := eos_opa.EnforcePolicy(context.Background(), policyPath, policyInput)
	if err != nil {
		return fmt.Errorf("policy evaluation failed: %w", err)
	}
	if len(denies) > 0 {
		return fmt.Errorf("policy denied: %v", denies)
	}

	return nil
}

func ValidateStructWithCUE(schema string, obj interface{}) error {
	// stub or CUE integration here
	return nil
}

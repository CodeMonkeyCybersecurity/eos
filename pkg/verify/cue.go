// pkg/verify/cue.go

package verify

import (
	"context"
	"fmt"
	"os"

	"cuelang.org/go/cue/load"
	"cuelang.org/go/encoding/yaml"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

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

	denies, err := EnforcePolicy(context.Background(), policyPath, policyInput)
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

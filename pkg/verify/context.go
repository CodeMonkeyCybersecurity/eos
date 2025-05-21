// pkg/verify/context.go

package verify

import (
	"context"
	"fmt"
)

func NewContext() *Context {
	return &Context{}
}

func (v *Context) ValidateAll(schema string, obj interface{}) error {
	// Validate with go-playground
	if err := ValidateStructWithGoPlayground(obj); err != nil {
		return err
	}

	// Validate with CUE schema
	if err := ValidateStructWithCUE(schema, obj); err != nil {
		return err
	}

	// Evaluate with OPA policy
	if ok, err := Evaluate(context.Background(), schema+".rego", obj); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("OPA policy validation failed for schema: %s", schema)
	}

	return nil
}

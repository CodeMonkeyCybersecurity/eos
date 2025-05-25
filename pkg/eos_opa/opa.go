// pkg/eos_opa/opa.go

package eos_opa

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	cerr "github.com/cockroachdb/errors"
	"github.com/go-playground/validator/v10"
	"github.com/open-policy-agent/opa/rego"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"
)

var (
	validate  = validator.New()
	policyDir = "policies" // overrideable if needed
	log       = zap.L().Named("opa")
)

// Enforce loads `<policyName>.rego`, evaluates `data.<policyName>.allow`
// against `input`, and returns nil iff allow == true.
func Enforce(ctx context.Context, policyName string, input interface{}) error {
	// — 1) Validate the policy name
	if err := validate.Var(policyName, "required,alphanum"); err != nil {
		return cerr.Wrapf(err, "invalid policy name %q", policyName)
	}

	// — 2) Telemetry span around the eval
	ctx, span := telemetry.Start(ctx, "OPA.Enforce",
		attribute.String("policy", policyName),
	)
	defer span.End()

	// — 3) Read the .rego file
	path := filepath.Join(policyDir, policyName+".rego")
	modBytes, err := os.ReadFile(path)
	if err != nil {
		log.Error("read policy file failed",
			zap.String("path", path), zap.Error(err))
		return cerr.Wrapf(err, "read policy %s", path)
	}

	// — 4) Build & Eval the query
	query := fmt.Sprintf("data.%s.allow", policyName)
	r := rego.New(
		rego.Query(query),
		rego.Module(policyName+".rego", string(modBytes)),
		rego.Input(input),
	)
	rs, err := r.Eval(ctx)
	if err != nil {
		log.Error("policy evaluation failed", zap.Error(err))
		return cerr.Wrapf(err, "policy %s evaluation failed", policyName)
	}
	if len(rs) == 0 {
		return cerr.Errorf("policy %s returned no result", policyName)
	}

	// — 5) Assert a boolean “allow” result
	v := rs[0].Expressions[0].Value
	allowed, ok := v.(bool)
	if !ok {
		return cerr.Errorf("policy %s returned non-boolean: %v", policyName, v)
	}
	if !allowed {
		return cerr.Errorf("policy %s denied", policyName)
	}

	return nil
}

// pkg/eos_opa/opa.go

package eos_opa

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	cerr "github.com/cockroachdb/errors"
	rego "github.com/open-policy-agent/opa/v1/rego"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"
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
		zap.L().Error("read policy file failed",
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
		zap.L().Error("policy evaluation failed", zap.Error(err))
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

func EnforcePolicy(ctx context.Context, policyPath string, input interface{}) ([]string, error) {

	query, err := rego.New(
		rego.Query("data.eos.tenant.deny"),
		rego.Load([]string{policyPath}, nil),
	).PrepareForEval(ctx)
	if err != nil {
		otelzap.Ctx(context.Background())
		return nil, err
	}

	rs, err := query.Eval(context.Background(), rego.EvalInput(input))
	if err != nil {
		otelzap.Ctx(context.Background())
		return nil, err
	}

	var messages []string
	for _, result := range rs {
		for _, expr := range result.Expressions {
			for _, msg := range expr.Value.([]interface{}) {
				messages = append(messages, msg.(string))
			}
		}
	}
	if len(messages) > 0 {
		otelzap.Ctx(context.Background())
	}
	return messages, nil
}

func Evaluate(ctx context.Context, policyName string, input any) (bool, error) {
	// Placeholder – always allow
	return true, nil
}

// compiledPolicy turns Rego source into a PreparedEvalQuery.
// MustCompile simply panics on error; explicit helper is clearer in prod.
func CompiledPolicy() rego.PreparedEvalQuery {
	const src = `package delphi
		default allow = false
		allow { input.level > 5 }`
	r := rego.New(rego.Query("allow"), rego.Module("policy.rego", src))
	pq, err := r.PrepareForEval(context.Background())
	if err != nil {
		panic(err)
	}
	return pq
}

// CompiledPolicyCtx is the context-aware sibling of CompiledPolicy.
// It returns a PreparedEvalQuery and any compilation error instead of panicking.
func CompiledPolicyCtx(ctx context.Context) (rego.PreparedEvalQuery, error) {
	const src = `package delphi
		default allow = false
		allow { input.level > 5 }`

	return rego.
		New(
			rego.Query("allow"),
			rego.Module("inline.rego", src),
		).
		PrepareForEval(ctx)
}

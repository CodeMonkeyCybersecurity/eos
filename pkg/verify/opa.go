// pkg/verify/opa.go

package verify

import (
	"context"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/open-policy-agent/opa/v1/rego"
	"go.uber.org/zap"
)

func EnforcePolicy(ctx context.Context, policyPath string, input interface{}) ([]string, error) {
	_, span := telemetry.Start(ctx, "verify.EnforcePolicy")
	defer span.End()

	query, err := rego.New(
		rego.Query("data.eos.tenant.deny"),
		rego.Load([]string{policyPath}, nil),
	).PrepareForEval(ctx)
	if err != nil {
		zap.L().Error("OPA policy load failed", zap.Error(err))
		span.RecordError(err)
		return nil, err
	}

	rs, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		zap.L().Error("OPA eval failed", zap.Error(err))
		span.RecordError(err)
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
		zap.L().Warn("Policy violations", zap.Strings("denies", messages))
	}
	return messages, nil
}

func Evaluate(ctx context.Context, policyName string, input any) (bool, error) {
	// Placeholder – always allow
	return true, nil
}

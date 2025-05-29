// pkg/verify/opa.go

package verify

import (
	"context"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

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

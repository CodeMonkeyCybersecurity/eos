package authentik

import (
	"context"
	"fmt"
	"strings"
)

// FindStage resolves an Authentik stage by identifier (name, slug, or UUID) and
// returns both the stage summary and the concrete stage type required for API lookups.
// The optional typeHint narrows the search (e.g., "identification").
func (c *APIClient) FindStage(ctx context.Context, identifier, typeHint string) (*StageResponse, string, error) {
	if strings.TrimSpace(identifier) == "" {
		return nil, "", fmt.Errorf("stage identifier is required")
	}

	stages, err := c.ListStages(ctx)
	if err != nil {
		return nil, "", err
	}

	stage, err := filterStageByIdentifier(stages, identifier, typeHint)
	if err != nil {
		return nil, "", err
	}

	stageType, err := determineStageType(stage, typeHint)
	if err != nil {
		return nil, "", err
	}

	return stage, stageType, nil
}

func filterStageByIdentifier(stages []StageResponse, identifier, typeHint string) (*StageResponse, error) {
	normalized := strings.ToLower(strings.TrimSpace(identifier))
	typeHintLower := strings.ToLower(strings.TrimSpace(typeHint))

	matches := make([]StageResponse, 0)
	for _, stage := range stages {
		if typeHintLower != "" && !stageMatchesType(stage, typeHintLower) {
			continue
		}

		switch {
		case strings.EqualFold(stage.PK, identifier):
			return &stage, nil
		case strings.EqualFold(stage.Name, identifier):
			matches = append(matches, stage)
		case normalized != "" && strings.Contains(strings.ToLower(stage.Name), normalized):
			matches = append(matches, stage)
		}
	}

	if len(matches) == 0 {
		return nil, fmt.Errorf("no stage matches identifier %q (type hint=%q)", identifier, typeHint)
	}
	if len(matches) > 1 {
		descriptions := make([]string, 0, len(matches))
		for _, stage := range matches {
			descriptions = append(descriptions, fmt.Sprintf("%s (pk=%s type=%s)", stage.Name, stage.PK, stage.Type))
		}
		return nil, fmt.Errorf("multiple stages match %q: %s. Provide --stage-type to disambiguate or use exact UUID",
			identifier, strings.Join(descriptions, ", "))
	}

	return &matches[0], nil
}

func stageMatchesType(stage StageResponse, typeHint string) bool {
	if strings.EqualFold(stage.Type, typeHint) {
		return true
	}
	componentLower := strings.ToLower(stage.Component)
	return typeHint != "" && componentLower != "" && strings.Contains(componentLower, typeHint)
}

func determineStageType(stage *StageResponse, hint string) (string, error) {
	if hint != "" {
		return strings.TrimSpace(hint), nil
	}

	if stage.Type != "" {
		return stage.Type, nil
	}

	component := strings.ToLower(stage.Component)
	if component == "" {
		return "", fmt.Errorf("unable to determine stage type for stage %s (%s)", stage.Name, stage.PK)
	}

	const marker = "authentik_stages_"
	idx := strings.Index(component, marker)
	if idx == -1 {
		return "", fmt.Errorf("cannot parse component %q for stage %s", stage.Component, stage.Name)
	}

	remainder := component[idx+len(marker):]
	if remainder == "" {
		return "", fmt.Errorf("component %q missing type suffix", stage.Component)
	}

	if dot := strings.IndexRune(remainder, '.'); dot != -1 {
		return remainder[:dot], nil
	}
	return remainder, nil
}

package build

import (
	"fmt"
	"sync"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// BuildOrchestrator manages building multiple components with dependency resolution
type BuildOrchestrator struct {
	config          *OrchestratorConfig
	dependencyGraph *DependencyGraph
}

// OrchestratorConfig holds configuration for the build orchestrator
type OrchestratorConfig struct {
	Tag             string   `json:"tag"`
	Registry        string   `json:"registry"`
	Push            bool     `json:"push"`
	Parallel        bool     `json:"parallel"`
	Force           bool     `json:"force"`
	Filter          string   `json:"filter"`
	Exclude         []string `json:"exclude"`
	ContinueOnError bool     `json:"continue_on_error"`
	DryRun          bool     `json:"dry_run"`
}

// Component represents a buildable component
type Component struct {
	Name         string            `json:"name"`
	Path         string            `json:"path"`
	Dependencies []string          `json:"dependencies"`
	BuildArgs    map[string]string `json:"build_args"`
	Dockerfile   string            `json:"dockerfile"`
	Context      string            `json:"context"`
}

// DependencyGraph represents the build dependency graph
type DependencyGraph struct {
	nodes map[string]*Component
	edges map[string][]string
}

// BuildBatch represents a batch of components that can be built in parallel
type BuildBatch struct {
	Components []*Component `json:"components"`
	BatchIndex int          `json:"batch_index"`
}

// NewBuildOrchestrator creates a new build orchestrator
func NewBuildOrchestrator(rc *eos_io.RuntimeContext, config *OrchestratorConfig) (*BuildOrchestrator, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Creating build orchestrator",
		zap.Bool("parallel", config.Parallel),
		zap.String("filter", config.Filter))

	return &BuildOrchestrator{
		config: config,
		dependencyGraph: &DependencyGraph{
			nodes: make(map[string]*Component),
			edges: make(map[string][]string),
		},
	}, nil
}

// DiscoverComponents discovers all buildable components in the workspace
func (bo *BuildOrchestrator) DiscoverComponents(rc *eos_io.RuntimeContext) ([]*Component, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Discovering buildable components")

	// Assessment: Scan workspace for components
	components, err := bo.scanWorkspaceForComponents(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to scan workspace: %w", err)
	}

	// Apply filters
	filtered := bo.applyFilters(components)

	// Build dependency graph
	if err := bo.buildDependencyGraph(rc, filtered); err != nil {
		return nil, fmt.Errorf("failed to build dependency graph: %w", err)
	}

	// Sort components by dependencies
	sorted, err := bo.topologicalSort(filtered)
	if err != nil {
		return nil, fmt.Errorf("failed to sort components by dependencies: %w", err)
	}

	logger.Info("Component discovery completed",
		zap.Int("total_found", len(components)),
		zap.Int("after_filter", len(filtered)),
		zap.Int("build_order", len(sorted)))

	return sorted, nil
}

// BuildAll builds all components following dependency order
func (bo *BuildOrchestrator) BuildAll(rc *eos_io.RuntimeContext, components []*Component) ([]*ComponentBuildResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting orchestrated build",
		zap.Int("component_count", len(components)),
		zap.Bool("parallel", bo.config.Parallel))

	var results []*ComponentBuildResult

	if bo.config.Parallel {
		// Build in parallel batches respecting dependencies
		batches := bo.createBuildBatches(components)

		for i, batch := range batches {
			logger.Info("Building batch",
				zap.Int("batch_index", i+1),
				zap.Int("batch_size", len(batch.Components)))

			batchResults, err := bo.buildBatch(rc, batch)
			if err != nil && !bo.config.ContinueOnError {
				logger.Error("Batch build failed", zap.Error(err))
				return append(results, batchResults...), err
			}
			results = append(results, batchResults...)
		}
	} else {
		// Build sequentially
		for _, component := range components {
			result, err := bo.buildComponent(rc, component)
			results = append(results, result)

			if err != nil && !bo.config.ContinueOnError {
				logger.Error("Component build failed, stopping",
					zap.String("component", component.Name),
					zap.Error(err))
				return results, err
			}
		}
	}

	logger.Info("Orchestrated build completed",
		zap.Int("total_components", len(components)),
		zap.Int("results", len(results)))

	return results, nil
}

// buildBatch builds a batch of components in parallel
func (bo *BuildOrchestrator) buildBatch(rc *eos_io.RuntimeContext, batch *BuildBatch) ([]*ComponentBuildResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	var results []*ComponentBuildResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	resultsChan := make(chan *ComponentBuildResult, len(batch.Components))
	errorsChan := make(chan error, len(batch.Components))

	// Build components in parallel
	for _, component := range batch.Components {
		wg.Add(1)
		go func(comp *Component) {
			defer wg.Done()

			logger.Debug("Building component in batch",
				zap.String("component", comp.Name),
				zap.Int("batch", batch.BatchIndex))

			result, err := bo.buildComponent(rc, comp)

			resultsChan <- result
			if err != nil {
				errorsChan <- err
			}
		}(component)
	}

	// Wait for all builds to complete
	wg.Wait()
	close(resultsChan)
	close(errorsChan)

	// Collect results
	for result := range resultsChan {
		mu.Lock()
		results = append(results, result)
		mu.Unlock()
	}

	// Check for errors
	var batchError error
	for err := range errorsChan {
		if batchError == nil {
			batchError = err
		}
		logger.Error("Component build failed in batch", zap.Error(err))
	}

	return results, batchError
}

// buildComponent builds a single component
func (bo *BuildOrchestrator) buildComponent(rc *eos_io.RuntimeContext, component *Component) (*ComponentBuildResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Building individual component",
		zap.String("component", component.Name))

	// Create component build config
	buildConfig := &ComponentBuildConfig{
		Name:      component.Name,
		Tag:       bo.config.Tag,
		Registry:  bo.config.Registry,
		Push:      bo.config.Push,
		Force:     bo.config.Force,
		BuildArgs: component.BuildArgs,
		DryRun:    bo.config.DryRun,
	}

	// Create and execute builder
	builder, err := NewComponentBuilder(rc, buildConfig)
	if err != nil {
		return &ComponentBuildResult{
			Component: component.Name,
			Success:   false,
			Error:     err.Error(),
		}, err
	}

	return builder.Build(rc)
}

// scanWorkspaceForComponents scans the workspace for buildable components
func (bo *BuildOrchestrator) scanWorkspaceForComponents(rc *eos_io.RuntimeContext) ([]*Component, error) {
	// Implementation would scan filesystem for Dockerfiles and component definitions
	// For now, return example components
	return []*Component{
		{
			Name:         "helen",
			Path:         "./helen",
			Dependencies: []string{},
			BuildArgs:    map[string]string{"ENV": "production"},
			Dockerfile:   "Dockerfile",
			Context:      "./helen",
		},
		{
			Name:         "api",
			Path:         "./api",
			Dependencies: []string{"base"},
			BuildArgs:    map[string]string{"PORT": "8080"},
			Dockerfile:   "Dockerfile",
			Context:      "./api",
		},
		{
			Name:         "frontend",
			Path:         "./frontend",
			Dependencies: []string{"api"},
			BuildArgs:    map[string]string{"NODE_ENV": "production"},
			Dockerfile:   "Dockerfile",
			Context:      "./frontend",
		},
	}, nil
}

// applyFilters applies include/exclude filters to components
func (bo *BuildOrchestrator) applyFilters(components []*Component) []*Component {
	var filtered []*Component

	for _, component := range components {
		// Apply exclude filter
		excluded := false
		for _, exclude := range bo.config.Exclude {
			if component.Name == exclude {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}

		// Apply include filter (if specified)
		if bo.config.Filter != "" {
			// Implementation would use regex matching
			// For now, simple string contains
			if component.Name != bo.config.Filter {
				continue
			}
		}

		filtered = append(filtered, component)
	}

	return filtered
}

// buildDependencyGraph builds the dependency graph for components
func (bo *BuildOrchestrator) buildDependencyGraph(rc *eos_io.RuntimeContext, components []*Component) error {
	// Add nodes
	for _, component := range components {
		bo.dependencyGraph.nodes[component.Name] = component
	}

	// Add edges
	for _, component := range components {
		bo.dependencyGraph.edges[component.Name] = component.Dependencies
	}

	// Validate no circular dependencies
	if err := bo.detectCircularDependencies(); err != nil {
		return fmt.Errorf("circular dependency detected: %w", err)
	}

	return nil
}

// topologicalSort sorts components by dependency order
func (bo *BuildOrchestrator) topologicalSort(components []*Component) ([]*Component, error) {
	var sorted []*Component
	visited := make(map[string]bool)
	inProgress := make(map[string]bool)

	var visit func(name string) error
	visit = func(name string) error {
		if inProgress[name] {
			return fmt.Errorf("circular dependency detected involving %s", name)
		}
		if visited[name] {
			return nil
		}

		inProgress[name] = true

		// Visit dependencies first
		for _, dep := range bo.dependencyGraph.edges[name] {
			if err := visit(dep); err != nil {
				return err
			}
		}

		inProgress[name] = false
		visited[name] = true

		// Add to sorted list
		if component := bo.dependencyGraph.nodes[name]; component != nil {
			sorted = append(sorted, component)
		}

		return nil
	}

	// Visit all components
	for _, component := range components {
		if err := visit(component.Name); err != nil {
			return nil, err
		}
	}

	return sorted, nil
}

// createBuildBatches creates batches of components that can be built in parallel
func (bo *BuildOrchestrator) createBuildBatches(components []*Component) []*BuildBatch {
	var batches []*BuildBatch
	processed := make(map[string]bool)

	batchIndex := 0
	for len(processed) < len(components) {
		var batchComponents []*Component

		// Find components whose dependencies are all processed
		for _, component := range components {
			if processed[component.Name] {
				continue
			}

			canBuild := true
			for _, dep := range component.Dependencies {
				if !processed[dep] {
					canBuild = false
					break
				}
			}

			if canBuild {
				batchComponents = append(batchComponents, component)
				processed[component.Name] = true
			}
		}

		if len(batchComponents) > 0 {
			batches = append(batches, &BuildBatch{
				Components: batchComponents,
				BatchIndex: batchIndex,
			})
			batchIndex++
		} else {
			// Safety check to prevent infinite loop
			break
		}
	}

	return batches
}

// detectCircularDependencies detects circular dependencies in the graph
func (bo *BuildOrchestrator) detectCircularDependencies() error {
	visited := make(map[string]bool)
	inProgress := make(map[string]bool)

	var visit func(name string) error
	visit = func(name string) error {
		if inProgress[name] {
			return fmt.Errorf("circular dependency detected at %s", name)
		}
		if visited[name] {
			return nil
		}

		inProgress[name] = true
		for _, dep := range bo.dependencyGraph.edges[name] {
			if err := visit(dep); err != nil {
				return err
			}
		}
		inProgress[name] = false
		visited[name] = true
		return nil
	}

	for name := range bo.dependencyGraph.nodes {
		if err := visit(name); err != nil {
			return err
		}
	}

	return nil
}

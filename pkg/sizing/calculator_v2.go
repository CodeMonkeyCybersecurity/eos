package sizing

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CalculatorV2 provides systematic hardware requirements calculation with detailed breakdown
type CalculatorV2 struct {
	workloadType   WorkloadType
	environment    string
	components     []string
	customFactors  map[string]ScalingFactors
	calculation    *CalculationBreakdown
}

// CalculationBreakdown shows detailed calculation steps and reasoning
type CalculationBreakdown struct {
	OSBaseline         ResourceCalculation            `json:"os_baseline"`
	ComponentDetails   map[string]ComponentCalculation `json:"component_details"`
	TotalBeforeScaling ResourceCalculation            `json:"total_before_scaling"`
	ScalingApplied     ScalingCalculation             `json:"scaling_applied"`
	FinalRequirements  ResourceCalculation            `json:"final_requirements"`
	NodeRecommendation NodeRecommendation             `json:"node_recommendation"`
	Warnings           []string                       `json:"warnings"`
	CalculationSteps   []CalculationStep              `json:"calculation_steps"`
	Timestamp          time.Time                      `json:"timestamp"`
}

// ResourceCalculation represents calculated resource requirements
type ResourceCalculation struct {
	CPU     float64 `json:"cpu_cores"`
	Memory  float64 `json:"memory_gb"`
	Storage float64 `json:"storage_gb"`
	IOPS    int     `json:"iops"`
	Network int     `json:"network_mbps"`
}

// ComponentCalculation shows how each component contributes to requirements
type ComponentCalculation struct {
	Component       string              `json:"component"`
	BaselineReqs    ResourceCalculation `json:"baseline_requirements"`
	ScaledReqs      ResourceCalculation `json:"scaled_requirements"`
	ScalingFactors  ScalingFactors      `json:"scaling_factors_used"`
	WorkloadImpact  WorkloadImpact      `json:"workload_impact"`
	References      []string            `json:"references"`
	Notes           string              `json:"notes"`
}

// WorkloadImpact shows how workload characteristics affect this component
type WorkloadImpact struct {
	UserImpact     float64 `json:"user_impact"`     // Additional resources for user load
	RequestImpact  float64 `json:"request_impact"`  // Additional resources for request load
	DataImpact     float64 `json:"data_impact"`     // Additional storage for data requirements
	LoadMultiplier float64 `json:"load_multiplier"` // Applied load multiplier
}

// ScalingCalculation shows what scaling factors were applied
type ScalingCalculation struct {
	EnvironmentFactor  float64 `json:"environment_factor"`  // Development/production multiplier
	SafetyMargin       float64 `json:"safety_margin"`       // Safety buffer applied
	GrowthBuffer       float64 `json:"growth_buffer"`       // Future growth accommodation
	PeakLoadBuffer     float64 `json:"peak_load_buffer"`    // Peak traffic accommodation
	TotalMultiplier    float64 `json:"total_multiplier"`    // Combined multiplier
}

// NodeRecommendation provides specific node configuration advice
type NodeRecommendation struct {
	RecommendedNodes int                `json:"recommended_nodes"`
	NodeSpecs        NodeSpecification  `json:"node_specs"`
	PlacementStrategy string            `json:"placement_strategy"`
	HAConsiderations  []string          `json:"ha_considerations"`
	CostEstimate      *CostBreakdown    `json:"cost_estimate,omitempty"`
}

// CostBreakdown provides detailed cost analysis
type CostBreakdown struct {
	MonthlyTotal     float64            `json:"monthly_total"`
	YearlyTotal      float64            `json:"yearly_total"`
	ComponentCosts   map[string]float64 `json:"component_costs"`
	Infrastructure   float64            `json:"infrastructure"`
	Network          float64            `json:"network"`
	Storage          float64            `json:"storage"`
	Currency         string             `json:"currency"`
}

// CalculationStep represents one step in the calculation process
type CalculationStep struct {
	Step        int    `json:"step"`
	Description string `json:"description"`
	Before      ResourceCalculation `json:"before"`
	After       ResourceCalculation `json:"after"`
	Reasoning   string `json:"reasoning"`
}

// WorkloadCharacteristics defines the expected workload for calculations
type WorkloadCharacteristics struct {
	ConcurrentUsers   int     `json:"concurrent_users"`
	RequestsPerSecond int     `json:"requests_per_second"`
	DataGrowthGB      float64 `json:"data_growth_gb"`
	PeakMultiplier    float64 `json:"peak_multiplier"`
	Type              WorkloadType `json:"type"`
}

// NewCalculatorV2 creates a new systematic calculator
func NewCalculatorV2(workloadType WorkloadType, environment string) *CalculatorV2 {
	return &CalculatorV2{
		workloadType:  workloadType,
		environment:   environment,
		components:    make([]string, 0),
		customFactors: make(map[string]ScalingFactors),
		calculation: &CalculationBreakdown{
			ComponentDetails: make(map[string]ComponentCalculation),
			CalculationSteps: make([]CalculationStep, 0),
			Warnings:         make([]string, 0),
			Timestamp:        time.Now(),
		},
	}
}

// AddComponent adds a component to the calculation
func (c *CalculatorV2) AddComponent(component string) error {
	if _, exists := RequirementsDatabase[component]; !exists {
		return fmt.Errorf("component %s not found in requirements database", component)
	}
	
	c.components = append(c.components, component)
	return nil
}

// SetCustomScalingFactors allows overriding default scaling factors for a component
func (c *CalculatorV2) SetCustomScalingFactors(component string, factors ScalingFactors) {
	c.customFactors[component] = factors
}

// Calculate performs the systematic calculation with detailed breakdown
func (c *CalculatorV2) Calculate(rc *eos_io.RuntimeContext, workload WorkloadCharacteristics) (*CalculationBreakdown, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Starting systematic hardware requirements calculation",
		zap.String("workload_type", string(c.workloadType)),
		zap.String("environment", c.environment),
		zap.Int("components", len(c.components)),
		zap.Int("concurrent_users", workload.ConcurrentUsers),
		zap.Int("requests_per_second", workload.RequestsPerSecond))

	// Step 1: Calculate OS baseline
	if err := c.calculateOSBaseline(rc); err != nil {
		return nil, fmt.Errorf("failed to calculate OS baseline: %w", err)
	}

	// Step 2: Calculate each component's requirements
	if err := c.calculateComponents(rc, workload); err != nil {
		return nil, fmt.Errorf("failed to calculate component requirements: %w", err)
	}

	// Step 3: Sum all requirements before scaling
	c.sumTotalRequirements(rc)

	// Step 4: Apply scaling factors
	if err := c.applyScalingFactors(rc, workload); err != nil {
		return nil, fmt.Errorf("failed to apply scaling factors: %w", err)
	}

	// Step 5: Generate node recommendations
	if err := c.generateNodeRecommendations(rc); err != nil {
		return nil, fmt.Errorf("failed to generate node recommendations: %w", err)
	}

	// Step 6: Validate and add warnings
	c.validateAndWarn(rc)

	logger.Info("Hardware requirements calculation completed",
		zap.Float64("final_cpu_cores", c.calculation.FinalRequirements.CPU),
		zap.Float64("final_memory_gb", c.calculation.FinalRequirements.Memory),
		zap.Float64("final_storage_gb", c.calculation.FinalRequirements.Storage),
		zap.Int("recommended_nodes", c.calculation.NodeRecommendation.RecommendedNodes))

	return c.calculation, nil
}

// calculateOSBaseline determines base operating system requirements
func (c *CalculatorV2) calculateOSBaseline(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	osReqs, exists := RequirementsDatabase["ubuntu_server_24.04"]
	if !exists {
		return fmt.Errorf("ubuntu server baseline requirements not found")
	}

	baseline := ResourceCalculation{
		CPU:     osReqs.BaselineOS.CPU.RecommendedCores,
		Memory:  osReqs.BaselineOS.Memory.RecommendedGB,
		Storage: osReqs.BaselineOS.Storage.RecommendedGB,
		Network: 100, // Basic network requirements
	}

	// Apply OS safety margin
	safetyMargin := osReqs.ScalingFactors.SafetyMargin
	baseline.CPU *= safetyMargin
	baseline.Memory *= safetyMargin
	baseline.Storage *= safetyMargin

	c.calculation.OSBaseline = baseline

	c.addCalculationStep(1, "Calculate Ubuntu Server 24.04 LTS baseline",
		ResourceCalculation{}, baseline,
		fmt.Sprintf("Applied %gx safety margin to OS baseline requirements", safetyMargin))

	logger.Info("Calculated OS baseline requirements",
		zap.Float64("cpu_cores", baseline.CPU),
		zap.Float64("memory_gb", baseline.Memory),
		zap.Float64("storage_gb", baseline.Storage),
		zap.Float64("safety_margin", safetyMargin))

	return nil
}

// calculateComponents calculates requirements for each component
func (c *CalculatorV2) calculateComponents(rc *eos_io.RuntimeContext, workload WorkloadCharacteristics) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	for _, component := range c.components {
		if err := c.calculateSingleComponent(rc, component, workload); err != nil {
			return fmt.Errorf("failed to calculate component %s: %w", component, err)
		}
	}

	logger.Info("Completed component calculations",
		zap.Int("total_components", len(c.components)))

	return nil
}

// calculateSingleComponent calculates requirements for one component
func (c *CalculatorV2) calculateSingleComponent(rc *eos_io.RuntimeContext, component string, workload WorkloadCharacteristics) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	req, exists := RequirementsDatabase[component]
	if !exists {
		return fmt.Errorf("component %s not found in requirements database", component)
	}

	// Start with baseline requirements
	baseline := ResourceCalculation{
		CPU:     req.ServiceReqs.Service.BaseRequirements.CPU.Cores,
		Memory:  req.ServiceReqs.Service.BaseRequirements.Memory.GB,
		Storage: req.ServiceReqs.Service.BaseRequirements.Disk.GB,
		IOPS:    req.ServiceReqs.Service.BaseRequirements.Disk.IOPS,
		Network: req.ServiceReqs.Service.BaseRequirements.Network.BandwidthMbps,
	}

	// Get scaling factors (custom or default)
	scalingFactors := req.ScalingFactors
	if custom, exists := c.customFactors[component]; exists {
		scalingFactors = custom
	}

	// Calculate workload impact
	workloadImpact := WorkloadImpact{
		UserImpact:     float64(workload.ConcurrentUsers) * scalingFactors.UserScaling,
		RequestImpact:  float64(workload.RequestsPerSecond) * scalingFactors.RequestScaling,
		DataImpact:     workload.DataGrowthGB * scalingFactors.DataScaling,
		LoadMultiplier: scalingFactors.LoadMultiplier,
	}

	// Apply workload scaling
	scaled := baseline
	scaled.CPU += workloadImpact.UserImpact + workloadImpact.RequestImpact
	scaled.Memory += workloadImpact.UserImpact * 0.1 // Assume 100MB memory per user impact unit
	scaled.Storage += workloadImpact.DataImpact

	// Apply load multiplier
	scaled.CPU *= workloadImpact.LoadMultiplier
	scaled.Memory *= workloadImpact.LoadMultiplier

	// Apply safety margin
	scaled.CPU *= scalingFactors.SafetyMargin
	scaled.Memory *= scalingFactors.SafetyMargin
	scaled.Storage *= scalingFactors.SafetyMargin

	// Store component calculation
	c.calculation.ComponentDetails[component] = ComponentCalculation{
		Component:      component,
		BaselineReqs:   baseline,
		ScaledReqs:     scaled,
		ScalingFactors: scalingFactors,
		WorkloadImpact: workloadImpact,
		References:     c.extractReferences(req),
		Notes:          req.Notes,
	}

	step := len(c.calculation.CalculationSteps) + 1
	c.addCalculationStep(step, fmt.Sprintf("Calculate %s requirements", component),
		baseline, scaled,
		fmt.Sprintf("Applied workload scaling (users: %d, rps: %d) and %gx safety margin",
			workload.ConcurrentUsers, workload.RequestsPerSecond, scalingFactors.SafetyMargin))

	logger.Info("Calculated component requirements",
		zap.String("component", component),
		zap.Float64("baseline_cpu", baseline.CPU),
		zap.Float64("scaled_cpu", scaled.CPU),
		zap.Float64("baseline_memory", baseline.Memory),
		zap.Float64("scaled_memory", scaled.Memory),
		zap.Float64("baseline_storage", baseline.Storage),
		zap.Float64("scaled_storage", scaled.Storage))

	return nil
}

// sumTotalRequirements calculates the sum of all component requirements
func (c *CalculatorV2) sumTotalRequirements(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)
	
	total := c.calculation.OSBaseline

	for component, calc := range c.calculation.ComponentDetails {
		total.CPU += calc.ScaledReqs.CPU
		total.Memory += calc.ScaledReqs.Memory
		total.Storage += calc.ScaledReqs.Storage
		total.IOPS += calc.ScaledReqs.IOPS
		total.Network = max(total.Network, calc.ScaledReqs.Network) // Take max network requirement
		
		logger.Debug("Adding component to total",
			zap.String("component", component),
			zap.Float64("component_cpu", calc.ScaledReqs.CPU),
			zap.Float64("component_memory", calc.ScaledReqs.Memory),
			zap.Float64("running_total_cpu", total.CPU),
			zap.Float64("running_total_memory", total.Memory))
	}

	c.calculation.TotalBeforeScaling = total

	step := len(c.calculation.CalculationSteps) + 1
	c.addCalculationStep(step, "Sum all component requirements",
		ResourceCalculation{}, total,
		"Added OS baseline + all component requirements")

	logger.Info("Calculated total requirements before environment scaling",
		zap.Float64("total_cpu", total.CPU),
		zap.Float64("total_memory", total.Memory),
		zap.Float64("total_storage", total.Storage),
		zap.Int("total_iops", total.IOPS))
}

// applyScalingFactors applies environment-specific scaling factors
func (c *CalculatorV2) applyScalingFactors(rc *eos_io.RuntimeContext, workload WorkloadCharacteristics) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Get environment configuration
	envConfig, exists := EnvironmentConfigs[c.environment]
	if !exists {
		return fmt.Errorf("environment configuration %s not found", c.environment)
	}

	scaling := ScalingCalculation{
		EnvironmentFactor: envConfig.OverprovisionRatio,
		GrowthBuffer:      envConfig.GrowthBuffer,
		PeakLoadBuffer:    workload.PeakMultiplier,
		SafetyMargin:      1.0, // Additional safety margin
	}

	// Calculate total multiplier
	scaling.TotalMultiplier = scaling.EnvironmentFactor * scaling.GrowthBuffer * scaling.PeakLoadBuffer

	// Apply to requirements
	beforeScaling := c.calculation.TotalBeforeScaling
	afterScaling := beforeScaling

	afterScaling.CPU *= scaling.TotalMultiplier
	afterScaling.Memory *= scaling.TotalMultiplier
	afterScaling.Storage *= scaling.GrowthBuffer // Storage grows more conservatively

	c.calculation.ScalingApplied = scaling
	c.calculation.FinalRequirements = afterScaling

	step := len(c.calculation.CalculationSteps) + 1
	c.addCalculationStep(step, "Apply environment and workload scaling",
		beforeScaling, afterScaling,
		fmt.Sprintf("Applied %gx total multiplier (%s environment: %gx, growth: %gx, peak load: %gx)",
			scaling.TotalMultiplier, c.environment, scaling.EnvironmentFactor, scaling.GrowthBuffer, scaling.PeakLoadBuffer))

	logger.Info("Applied scaling factors",
		zap.String("environment", c.environment),
		zap.Float64("environment_factor", scaling.EnvironmentFactor),
		zap.Float64("growth_buffer", scaling.GrowthBuffer),
		zap.Float64("peak_load_buffer", scaling.PeakLoadBuffer),
		zap.Float64("total_multiplier", scaling.TotalMultiplier),
		zap.Float64("final_cpu", afterScaling.CPU),
		zap.Float64("final_memory", afterScaling.Memory))

	return nil
}

// generateNodeRecommendations determines optimal node configuration
func (c *CalculatorV2) generateNodeRecommendations(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	envConfig := EnvironmentConfigs[c.environment]
	total := c.calculation.FinalRequirements

	// Calculate minimum nodes needed for HA
	minNodes := 1
	if c.environment == "production" {
		minNodes = 3 // Minimum for production HA
	}

	// Calculate how many nodes fit within max node size
	maxNodeCPU := float64(envConfig.MaxNodeSize.CPUCores)
	maxNodeMemory := float64(envConfig.MaxNodeSize.MemoryGB)
	
	nodesByCD := int(math.Ceil(total.CPU / maxNodeCPU))
	nodesByMemory := int(math.Ceil(total.Memory / maxNodeMemory))
	
	nodesNeeded := max(max(nodesByCD, nodesByMemory), minNodes)

	// Calculate per-node specs
	nodeSpecs := NodeSpecification{
		CPUCores:       int(math.Ceil(total.CPU / float64(nodesNeeded))),
		MemoryGB:       int(math.Ceil(total.Memory / float64(nodesNeeded))),
		DiskGB:         int(math.Ceil(total.Storage / float64(nodesNeeded))),
		DiskType:       "ssd", // Default to SSD for performance
		NetworkGbps:    max(1, total.Network/1000), // Convert Mbps to Gbps
	}

	// Ensure specs meet minimum requirements
	if nodeSpecs.CPUCores < envConfig.MinNodeSize.CPUCores {
		nodeSpecs.CPUCores = envConfig.MinNodeSize.CPUCores
	}
	if nodeSpecs.MemoryGB < envConfig.MinNodeSize.MemoryGB {
		nodeSpecs.MemoryGB = envConfig.MinNodeSize.MemoryGB
	}
	if nodeSpecs.DiskGB < envConfig.MinNodeSize.DiskGB {
		nodeSpecs.DiskGB = envConfig.MinNodeSize.DiskGB
	}

	// Calculate utilization after specs are finalized
	nodeSpecs.CPUUtilization = (total.CPU / float64(nodesNeeded)) / float64(nodeSpecs.CPUCores)
	nodeSpecs.MemUtilization = (total.Memory / float64(nodesNeeded)) / float64(nodeSpecs.MemoryGB)

	// Generate HA considerations
	haConsiderations := []string{
		"Deploy across multiple availability zones if possible",
		"Ensure network latency between nodes is < 10ms for consensus protocols",
		"Configure automated backups for persistent data",
	}

	if c.environment == "production" {
		haConsiderations = append(haConsiderations,
			"Use odd number of nodes (3, 5, 7) for consensus protocols",
			"Implement monitoring and alerting for node health",
			"Plan for rolling updates with zero downtime")
	}

	c.calculation.NodeRecommendation = NodeRecommendation{
		RecommendedNodes:  nodesNeeded,
		NodeSpecs:         nodeSpecs,
		PlacementStrategy: "spread", // Default to spreading across nodes
		HAConsiderations:  haConsiderations,
	}

	step := len(c.calculation.CalculationSteps) + 1
	c.addCalculationStep(step, "Generate node recommendations",
		ResourceCalculation{}, ResourceCalculation{
			CPU:     float64(nodesNeeded * nodeSpecs.CPUCores),
			Memory:  float64(nodesNeeded * nodeSpecs.MemoryGB),
			Storage: float64(nodesNeeded * nodeSpecs.DiskGB),
		},
		fmt.Sprintf("Recommended %d nodes of %d cores/%dGB memory each for %s environment",
			nodesNeeded, nodeSpecs.CPUCores, nodeSpecs.MemoryGB, c.environment))

	logger.Info("Generated node recommendations",
		zap.Int("recommended_nodes", nodesNeeded),
		zap.Int("node_cpu_cores", nodeSpecs.CPUCores),
		zap.Int("node_memory_gb", nodeSpecs.MemoryGB),
		zap.Int("node_disk_gb", nodeSpecs.DiskGB),
		zap.Float64("cpu_utilization", nodeSpecs.CPUUtilization),
		zap.Float64("memory_utilization", nodeSpecs.MemUtilization))

	return nil
}

// validateAndWarn adds warnings for potential issues
func (c *CalculatorV2) validateAndWarn(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)
	
	final := c.calculation.FinalRequirements
	nodeRec := c.calculation.NodeRecommendation

	// Check for very high resource requirements
	if final.CPU > 64 {
		warning := fmt.Sprintf("Very high CPU requirement (%.1f cores) - consider workload optimization", final.CPU)
		c.calculation.Warnings = append(c.calculation.Warnings, warning)
		logger.Warn(warning)
	}

	if final.Memory > 256 {
		warning := fmt.Sprintf("Very high memory requirement (%.1f GB) - consider workload optimization", final.Memory)
		c.calculation.Warnings = append(c.calculation.Warnings, warning)
		logger.Warn(warning)
	}

	// Check for underutilized nodes
	if nodeRec.NodeSpecs.CPUUtilization < 0.3 {
		warning := "Low CPU utilization predicted - consider smaller nodes or consolidation"
		c.calculation.Warnings = append(c.calculation.Warnings, warning)
		logger.Warn(warning)
	}

	if nodeRec.NodeSpecs.MemUtilization < 0.3 {
		warning := "Low memory utilization predicted - consider smaller nodes or consolidation"
		c.calculation.Warnings = append(c.calculation.Warnings, warning)
		logger.Warn(warning)
	}

	// Check for single node deployment in production
	if c.environment == "production" && nodeRec.RecommendedNodes == 1 {
		warning := "Single node deployment is not recommended for production - consider HA setup"
		c.calculation.Warnings = append(c.calculation.Warnings, warning)
		logger.Warn(warning)
	}

	// Check for missing IOPS requirements
	if final.IOPS > 10000 {
		warning := fmt.Sprintf("High IOPS requirement (%d) - ensure storage can meet performance needs", final.IOPS)
		c.calculation.Warnings = append(c.calculation.Warnings, warning)
		logger.Warn(warning)
	}

	logger.Info("Validation completed",
		zap.Int("warnings_generated", len(c.calculation.Warnings)))
}

// Helper functions

func (c *CalculatorV2) addCalculationStep(step int, description string, before, after ResourceCalculation, reasoning string) {
	c.calculation.CalculationSteps = append(c.calculation.CalculationSteps, CalculationStep{
		Step:        step,
		Description: description,
		Before:      before,
		After:       after,
		Reasoning:   reasoning,
	})
}

func (c *CalculatorV2) extractReferences(req SystemRequirements) []string {
	references := make([]string, len(req.References))
	for i, ref := range req.References {
		if ref.URL != "" {
			references[i] = fmt.Sprintf("%s: %s", ref.Description, ref.URL)
		} else {
			references[i] = ref.Description
		}
	}
	return references
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// GenerateHumanReadableReport creates a detailed report of the calculation
func (c *CalculatorV2) GenerateHumanReadableReport() string {
	var report strings.Builder
	
	report.WriteString("=== Hardware Requirements Calculation Report ===\n\n")
	
	// Summary
	final := c.calculation.FinalRequirements
	nodes := c.calculation.NodeRecommendation
	
	report.WriteString("SUMMARY:\n")
	report.WriteString(fmt.Sprintf("• Total CPU Cores: %.1f\n", final.CPU))
	report.WriteString(fmt.Sprintf("• Total Memory: %.1f GB\n", final.Memory))
	report.WriteString(fmt.Sprintf("• Total Storage: %.1f GB\n", final.Storage))
	report.WriteString(fmt.Sprintf("• Recommended Nodes: %d\n", nodes.RecommendedNodes))
	report.WriteString(fmt.Sprintf("• Per-Node Specs: %d cores, %d GB memory, %d GB storage\n\n",
		nodes.NodeSpecs.CPUCores, nodes.NodeSpecs.MemoryGB, nodes.NodeSpecs.DiskGB))
	
	// OS Baseline
	os := c.calculation.OSBaseline
	report.WriteString("OS BASELINE (Ubuntu Server 24.04 LTS):\n")
	report.WriteString(fmt.Sprintf("• CPU: %.1f cores\n", os.CPU))
	report.WriteString(fmt.Sprintf("• Memory: %.1f GB\n", os.Memory))
	report.WriteString(fmt.Sprintf("• Storage: %.1f GB\n\n", os.Storage))
	
	// Component Breakdown
	report.WriteString("COMPONENT BREAKDOWN:\n")
	for component, calc := range c.calculation.ComponentDetails {
		report.WriteString(fmt.Sprintf("• %s:\n", component))
		report.WriteString(fmt.Sprintf("  - Baseline: %.1f cores, %.1f GB memory, %.1f GB storage\n",
			calc.BaselineReqs.CPU, calc.BaselineReqs.Memory, calc.BaselineReqs.Storage))
		report.WriteString(fmt.Sprintf("  - After scaling: %.1f cores, %.1f GB memory, %.1f GB storage\n",
			calc.ScaledReqs.CPU, calc.ScaledReqs.Memory, calc.ScaledReqs.Storage))
		if calc.Notes != "" {
			report.WriteString(fmt.Sprintf("  - Notes: %s\n", calc.Notes))
		}
		report.WriteString("\n")
	}
	
	// Scaling Applied
	scaling := c.calculation.ScalingApplied
	report.WriteString("SCALING FACTORS APPLIED:\n")
	report.WriteString(fmt.Sprintf("• Environment factor (%s): %.1fx\n", c.environment, scaling.EnvironmentFactor))
	report.WriteString(fmt.Sprintf("• Growth buffer: %.1fx\n", scaling.GrowthBuffer))
	report.WriteString(fmt.Sprintf("• Peak load buffer: %.1fx\n", scaling.PeakLoadBuffer))
	report.WriteString(fmt.Sprintf("• Total multiplier: %.1fx\n\n", scaling.TotalMultiplier))
	
	// Warnings
	if len(c.calculation.Warnings) > 0 {
		report.WriteString("WARNINGS:\n")
		for _, warning := range c.calculation.Warnings {
			report.WriteString(fmt.Sprintf("⚠️  %s\n", warning))
		}
		report.WriteString("\n")
	}
	
	// HA Considerations
	if len(nodes.HAConsiderations) > 0 {
		report.WriteString("HIGH AVAILABILITY CONSIDERATIONS:\n")
		for _, consideration := range nodes.HAConsiderations {
			report.WriteString(fmt.Sprintf("• %s\n", consideration))
		}
		report.WriteString("\n")
	}
	
	report.WriteString(fmt.Sprintf("Report generated: %s\n", c.calculation.Timestamp.Format("2006-01-02 15:04:05 UTC")))
	
	return report.String()
}
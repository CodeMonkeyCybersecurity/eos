// pkg/mozart/orchestrator

package mozart

import (
	"fmt"
	"log"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/jenkins"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/salt"
)

// DeploymentOrchestrator coordinates deployments using Jenkins and Salt
type DeploymentOrchestrator struct {
	Jenkins *jenkins.Client
	Salt    *salt.Client
}

// DeploymentRequest represents a deployment request
type DeploymentRequest struct {
	Application string
	Version     string
	Environment string
	Strategy    string // "rolling", "blue-green", "canary"
}

// DeployApplication orchestrates a full deployment
func (o *DeploymentOrchestrator) DeployApplication(req DeploymentRequest) error {
	log.Printf("Starting deployment of %s version %s to %s using %s strategy",
		req.Application, req.Version, req.Environment, req.Strategy)

	// Step 1: Trigger Jenkins build
	buildParams := jenkins.BuildParameters{
		"VERSION":     req.Version,
		"ENVIRONMENT": req.Environment,
	}

	err := o.Jenkins.TriggerBuild(req.Application, buildParams)
	if err != nil {
		return fmt.Errorf("failed to trigger build: %w", err)
	}

	// Step 2: Wait for build to complete
	// In a real implementation, you'd get the actual build number
	build, err := o.Jenkins.WaitForBuild(req.Application, 100, 30*time.Minute)
	if err != nil {
		return fmt.Errorf("build failed or timed out: %w", err)
	}

	if build.Result != "SUCCESS" {
		return fmt.Errorf("build failed with result: %s", build.Result)
	}

	// Step 3: Prepare infrastructure with Salt
	log.Println("Preparing infrastructure...")

	target := fmt.Sprintf("G@environment:%s and G@role:%s", req.Environment, req.Application)
	_, err = o.Salt.ApplyState(
		target,
		"compound", // Use compound matching for grains
		"prepare_deployment",
		map[string]interface{}{
			"version": req.Version,
		},
	)
	if err != nil {
		return fmt.Errorf("failed to prepare infrastructure: %w", err)
	}

	// Step 4: Execute deployment based on strategy
	switch req.Strategy {
	case "rolling":
		return o.rollingDeployment(req)
	case "blue-green":
		return o.blueGreenDeployment(req)
	case "canary":
		return o.canaryDeployment(req)
	default:
		return fmt.Errorf("unknown deployment strategy: %s", req.Strategy)
	}
}

// rollingDeployment performs a rolling deployment
func (o *DeploymentOrchestrator) rollingDeployment(req DeploymentRequest) error {
	target := fmt.Sprintf("G@environment:%s and G@role:%s", req.Environment, req.Application)

	// Get list of minions
	grainResult, err := o.Salt.GetGrains(target, "compound", []string{"id"})
	if err != nil {
		return fmt.Errorf("failed to get minion list: %w", err)
	}

	minions := make([]string, 0, len(grainResult))
	for minion := range grainResult {
		minions = append(minions, minion)
	}

	log.Printf("Performing rolling deployment to %d servers", len(minions))

	// Deploy to servers in batches
	batchSize := len(minions) / 4 // 25% at a time
	if batchSize < 1 {
		batchSize = 1
	}

	for i := 0; i < len(minions); i += batchSize {
		end := i + batchSize
		if end > len(minions) {
			end = len(minions)
		}

		batch := minions[i:end]
		log.Printf("Deploying to batch %d/%d: %v", i/batchSize+1, (len(minions)+batchSize-1)/batchSize, batch)

		// Deploy to this batch
		for _, minion := range batch {
			_, err := o.Salt.ApplyState(
				minion,
				"glob",
				"deploy_application",
				map[string]interface{}{
					"application": req.Application,
					"version":     req.Version,
				},
			)
			if err != nil {
				return fmt.Errorf("deployment to %s failed: %w", minion, err)
			}
		}

		// Health check the batch
		time.Sleep(30 * time.Second) // Give services time to start

		healthResult, err := o.Salt.RunCommand(
			fmt.Sprintf("L@%s", batch),
			"list",
			"cmd.run",
			[]interface{}{fmt.Sprintf("curl -f http://localhost/%s/health", req.Application)},
			nil,
		)
		if err != nil {
			return fmt.Errorf("health check failed: %w", err)
		}

		// Check if all servers in batch are healthy
		for minion, result := range healthResult {
			if result == nil {
				return fmt.Errorf("server %s failed health check", minion)
			}
		}

		log.Printf("Batch %d/%d deployed successfully", i/batchSize+1, (len(minions)+batchSize-1)/batchSize)
	}

	return nil
}

// canaryDeployment performs a canary deployment with gradual rollout
func (o *DeploymentOrchestrator) canaryDeployment(req DeploymentRequest) error {
	// Implementation would gradually increase the percentage of servers
	// running the new version while monitoring metrics
	log.Println("Canary deployment not yet implemented")
	return nil
}

// blueGreenDeployment performs a blue-green deployment
func (o *DeploymentOrchestrator) blueGreenDeployment(req DeploymentRequest) error {
	// Implementation would deploy to the inactive color, test it,
	// then switch the load balancer
	log.Println("Blue-green deployment not yet implemented")
	return nil
}

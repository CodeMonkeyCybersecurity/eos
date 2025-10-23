// pkg/bionicgpt_nomad/nomad.go - Phase 6: Nomad deployment

package bionicgpt_nomad

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/nomad"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/templates"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DeployNomad deploys BionicGPT stack to Nomad
func (ei *EnterpriseInstaller) DeployNomad() error {
	logger := otelzap.Ctx(ei.rc.Ctx)

	logger.Info("Phase 6: Deploying BionicGPT to Nomad")

	// Create Nomad client
	zapLogger := zap.NewNop()
	nomadClient, err := nomad.NewClient(ei.config.NomadAddress, zapLogger)
	if err != nil {
		return fmt.Errorf("failed to create Nomad client: %w", err)
	}

	// Step 1: Deploy PostgreSQL
	logger.Info("  [1/5] Deploying PostgreSQL")
	if err := ei.deployPostgreSQL(nomadClient); err != nil {
		return fmt.Errorf("failed to deploy PostgreSQL: %w", err)
	}
	logger.Info("    ✓ PostgreSQL deployed")

	// Step 2: Wait for PostgreSQL to be healthy
	logger.Info("  [2/5] Waiting for PostgreSQL to be healthy")
	postgresJobID := fmt.Sprintf("%s-bionicgpt-postgres", ei.config.Namespace)
	if err := nomadClient.WaitForJobRunning(ei.rc.Ctx, postgresJobID, 3*time.Minute); err != nil {
		return fmt.Errorf("PostgreSQL failed to become healthy: %w", err)
	}
	logger.Info("    ✓ PostgreSQL is healthy")

	// Step 3: Deploy LiteLLM (if Azure configured)
	if ei.config.AzureEndpoint != "" && ei.config.AzureChatDeployment != "" {
		logger.Info("  [3/5] Deploying LiteLLM proxy")
		if err := ei.deployLiteLLM(nomadClient); err != nil {
			return fmt.Errorf("failed to deploy LiteLLM: %w", err)
		}
		logger.Info("    ✓ LiteLLM deployed")

		litellmJobID := fmt.Sprintf("%s-litellm", ei.config.Namespace)
		if err := nomadClient.WaitForJobRunning(ei.rc.Ctx, litellmJobID, 2*time.Minute); err != nil {
			return fmt.Errorf("LiteLLM failed to become healthy: %w", err)
		}
		logger.Info("    ✓ LiteLLM is healthy")
	} else {
		logger.Info("  [3/5] Skipping LiteLLM (no Azure configuration)")
	}

	// Step 4: Deploy Ollama (if local embeddings enabled)
	if ei.config.UseLocalEmbeddings {
		logger.Info("  [4/5] Deploying Ollama for local embeddings")
		if err := ei.deployOllama(nomadClient); err != nil {
			return fmt.Errorf("failed to deploy Ollama: %w", err)
		}
		logger.Info("    ✓ Ollama deployed")

		ollamaJobID := fmt.Sprintf("%s-ollama", ei.config.Namespace)
		if err := nomadClient.WaitForJobRunning(ei.rc.Ctx, ollamaJobID, 2*time.Minute); err != nil {
			return fmt.Errorf("Ollama failed to become healthy: %w", err)
		}
		logger.Info("    ✓ Ollama is healthy")
	} else {
		logger.Info("  [4/5] Skipping Ollama (using remote embeddings)")
	}

	// Step 5: Deploy BionicGPT + oauth2-proxy
	logger.Info("  [5/5] Deploying BionicGPT application")
	if err := ei.deployBionicGPT(nomadClient); err != nil {
		return fmt.Errorf("failed to deploy BionicGPT: %w", err)
	}
	logger.Info("    ✓ BionicGPT deployed")

	bionicgptJobID := fmt.Sprintf("%s-bionicgpt", ei.config.Namespace)
	if err := nomadClient.WaitForJobRunning(ei.rc.Ctx, bionicgptJobID, 3*time.Minute); err != nil {
		return fmt.Errorf("BionicGPT failed to become healthy: %w", err)
	}
	logger.Info("    ✓ BionicGPT is healthy")

	logger.Info("✓ Nomad deployment complete")
	return nil
}

// deployPostgreSQL deploys PostgreSQL with pgVector
func (ei *EnterpriseInstaller) deployPostgreSQL(client *nomad.Client) error {
	logger := otelzap.Ctx(ei.rc.Ctx)

	// Check if job already exists
	jobID := fmt.Sprintf("%s-bionicgpt-postgres", ei.config.Namespace)
	exists, err := client.JobExists(ei.rc.Ctx, jobID)
	if err != nil {
		return fmt.Errorf("failed to check if PostgreSQL job exists: %w", err)
	}

	if exists && !ei.config.Force {
		logger.Info("    PostgreSQL job already exists (use --force to redeploy)")
		return nil
	}

	// Render template
	templateData := ei.buildTemplateData()
	renderer := templates.NewRenderer(nil)
	rendered, err := renderer.RenderEmbedded(
		ei.rc.Ctx,
		templatesFS,
		"templates/postgres.nomad.hcl.tmpl",
		templateData,
		nil,
	)
	if err != nil {
		return fmt.Errorf("failed to render PostgreSQL template: %w", err)
	}

	logger.Debug("    Rendered PostgreSQL job HCL", zap.Int("size", len(rendered)))

	// Parse HCL to Nomad job
	job, err := client.ParseHCL(rendered)
	if err != nil {
		return fmt.Errorf("failed to parse PostgreSQL job HCL: %w", err)
	}

	// Submit job to Nomad
	_, err = client.SubmitJob(ei.rc.Ctx, job)
	if err != nil {
		return fmt.Errorf("failed to submit PostgreSQL job: %w", err)
	}

	logger.Info("    PostgreSQL job submitted successfully", zap.String("job_id", jobID))
	return nil
}

// deployLiteLLM deploys LiteLLM proxy for Azure OpenAI
func (ei *EnterpriseInstaller) deployLiteLLM(client *nomad.Client) error {
	logger := otelzap.Ctx(ei.rc.Ctx)

	// Check if job already exists
	jobID := fmt.Sprintf("%s-litellm", ei.config.Namespace)
	exists, err := client.JobExists(ei.rc.Ctx, jobID)
	if err != nil {
		return fmt.Errorf("failed to check if LiteLLM job exists: %w", err)
	}

	if exists && !ei.config.Force {
		logger.Info("    LiteLLM job already exists (use --force to redeploy)")
		return nil
	}

	// Render template
	templateData := ei.buildTemplateData()
	renderer := templates.NewRenderer(nil)
	rendered, err := renderer.RenderEmbedded(
		ei.rc.Ctx,
		templatesFS,
		"templates/litellm.nomad.hcl.tmpl",
		templateData,
		nil,
	)
	if err != nil {
		return fmt.Errorf("failed to render LiteLLM template: %w", err)
	}

	logger.Debug("    Rendered LiteLLM job HCL", zap.Int("size", len(rendered)))

	// Parse HCL to Nomad job
	job, err := client.ParseHCL(rendered)
	if err != nil {
		return fmt.Errorf("failed to parse LiteLLM job HCL: %w", err)
	}

	// Submit job to Nomad
	_, err = client.SubmitJob(ei.rc.Ctx, job)
	if err != nil {
		return fmt.Errorf("failed to submit LiteLLM job: %w", err)
	}

	logger.Info("    LiteLLM job submitted successfully", zap.String("job_id", jobID))
	return nil
}

// deployOllama deploys Ollama for local embeddings
func (ei *EnterpriseInstaller) deployOllama(client *nomad.Client) error {
	logger := otelzap.Ctx(ei.rc.Ctx)

	// Check if job already exists
	jobID := fmt.Sprintf("%s-ollama", ei.config.Namespace)
	exists, err := client.JobExists(ei.rc.Ctx, jobID)
	if err != nil {
		return fmt.Errorf("failed to check if Ollama job exists: %w", err)
	}

	if exists && !ei.config.Force {
		logger.Info("    Ollama job already exists (use --force to redeploy)")
		return nil
	}

	// Render template
	templateData := ei.buildTemplateData()
	renderer := templates.NewRenderer(nil)
	rendered, err := renderer.RenderEmbedded(
		ei.rc.Ctx,
		templatesFS,
		"templates/ollama.nomad.hcl.tmpl",
		templateData,
		nil,
	)
	if err != nil {
		return fmt.Errorf("failed to render Ollama template: %w", err)
	}

	logger.Debug("    Rendered Ollama job HCL", zap.Int("size", len(rendered)))

	// Parse HCL to Nomad job
	job, err := client.ParseHCL(rendered)
	if err != nil {
		return fmt.Errorf("failed to parse Ollama job HCL: %w", err)
	}

	// Submit job to Nomad
	_, err = client.SubmitJob(ei.rc.Ctx, job)
	if err != nil {
		return fmt.Errorf("failed to submit Ollama job: %w", err)
	}

	logger.Info("    Ollama job submitted successfully", zap.String("job_id", jobID))
	return nil
}

// deployBionicGPT deploys BionicGPT application with oauth2-proxy
func (ei *EnterpriseInstaller) deployBionicGPT(client *nomad.Client) error {
	logger := otelzap.Ctx(ei.rc.Ctx)

	// Check if job already exists
	jobID := fmt.Sprintf("%s-bionicgpt", ei.config.Namespace)
	exists, err := client.JobExists(ei.rc.Ctx, jobID)
	if err != nil {
		return fmt.Errorf("failed to check if BionicGPT job exists: %w", err)
	}

	if exists && !ei.config.Force {
		logger.Info("    BionicGPT job already exists (use --force to redeploy)")
		return nil
	}

	// Render template
	templateData := ei.buildTemplateData()
	renderer := templates.NewRenderer(nil)
	rendered, err := renderer.RenderEmbedded(
		ei.rc.Ctx,
		templatesFS,
		"templates/bionicgpt.nomad.hcl.tmpl",
		templateData,
		nil,
	)
	if err != nil {
		return fmt.Errorf("failed to render BionicGPT template: %w", err)
	}

	logger.Debug("    Rendered BionicGPT job HCL", zap.Int("size", len(rendered)))

	// Parse HCL to Nomad job
	job, err := client.ParseHCL(rendered)
	if err != nil {
		return fmt.Errorf("failed to parse BionicGPT job HCL: %w", err)
	}

	// Submit job to Nomad
	_, err = client.SubmitJob(ei.rc.Ctx, job)
	if err != nil {
		return fmt.Errorf("failed to submit BionicGPT job: %w", err)
	}

	logger.Info("    BionicGPT job submitted successfully", zap.String("job_id", jobID))
	return nil
}

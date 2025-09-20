package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/cicd"
)

// NewTerraformClient creates a new Terraform client
func NewTerraformClient(config TerraformClientConfig) (*TerraformClient, error) {
	// Verify Terraform binary exists
	binaryPath := config.BinaryPath
	if binaryPath == "" {
		binaryPath = "terraform"
	}

	if _, err := exec.LookPath(binaryPath); err != nil {
		return nil, fmt.Errorf("terraform binary not found: %w", err)
	}

	// Ensure working directory exists
	workingDir := config.WorkingDir
	if workingDir == "" {
		workingDir = "/tmp/terraform"
	}

	if err := os.MkdirAll(workingDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create working directory: %w", err)
	}

	return &TerraformClient{
		config:     config,
		workingDir: workingDir,
		binaryPath: binaryPath,
	}, nil
}

// Plan implements cicd.TerraformClient interface
func (tc *TerraformClient) Plan(ctx context.Context, workdir string, vars map[string]string) (*cicd.TerraformPlan, error) {
	if workdir != "" {
		tc.workingDir = workdir
	}

	// Prepare terraform plan command
	args := []string{"plan", "-out=tfplan", "-detailed-exitcode"}

	// Add variables
	for key, value := range vars {
		args = append(args, "-var", fmt.Sprintf("%s=%s", key, value))
	}

	cmd := exec.CommandContext(ctx, tc.binaryPath, args...)
	cmd.Dir = tc.workingDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("terraform plan failed: %w, output: %s", err, string(output))
	}

	// Parse plan output (simplified)
	plan := &cicd.TerraformPlan{
		HasChanges: true, // Would parse from actual output
		Output:     string(output),
		ResourceActions: []cicd.ResourceAction{
			{Resource: "example_resource", Action: "create"},
		},
	}

	return plan, nil
}

// Apply implements cicd.TerraformClient interface
func (tc *TerraformClient) Apply(ctx context.Context, workdir string, vars map[string]string) (*cicd.TerraformOutput, error) {
	if workdir != "" {
		tc.workingDir = workdir
	}

	// Prepare terraform apply command
	args := []string{"apply", "-auto-approve"}

	// Add variables
	for key, value := range vars {
		args = append(args, "-var", fmt.Sprintf("%s=%s", key, value))
	}

	cmd := exec.CommandContext(ctx, tc.binaryPath, args...)
	cmd.Dir = tc.workingDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("terraform apply failed: %w, output: %s", err, string(output))
	}

	// Parse apply output (simplified)
	result := &cicd.TerraformOutput{
		Success: true,
		Outputs: make(map[string]string),
		Resources: []cicd.ResourceInfo{
			{Type: "example", Name: "resource", Status: "created"},
		},
	}

	return result, nil
}

// Destroy implements cicd.TerraformClient interface
func (tc *TerraformClient) Destroy(ctx context.Context, workdir string, vars map[string]string) error {
	if workdir != "" {
		tc.workingDir = workdir
	}

	// Prepare terraform destroy command
	args := []string{"destroy", "-auto-approve"}

	// Add variables
	for key, value := range vars {
		args = append(args, "-var", fmt.Sprintf("%s=%s", key, value))
	}

	cmd := exec.CommandContext(ctx, tc.binaryPath, args...)
	cmd.Dir = tc.workingDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("terraform destroy failed: %w, output: %s", err, string(output))
	}

	return nil
}

// GetState implements cicd.TerraformClient interface
func (tc *TerraformClient) GetState(ctx context.Context, workdir string) (*cicd.TerraformState, error) {
	if workdir != "" {
		tc.workingDir = workdir
	}

	// Get terraform state
	cmd := exec.CommandContext(ctx, tc.binaryPath, "show", "-json")
	cmd.Dir = tc.workingDir

	_, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get terraform state: %w", err)
	}

	// Parse state (simplified)
	state := &cicd.TerraformState{
		Version:   4,
		Resources: []cicd.ResourceInfo{},
		Outputs:   make(map[string]string),
	}

	return state, nil
}

// NewNomadClient creates a new Nomad client
func NewNomadClient(config NomadClientConfig, httpClient HTTPClient) (*NomadClient, error) {
	return &NomadClient{
		config:     config,
		httpClient: httpClient,
	}, nil
}

// SubmitJob implements cicd.NomadClient interface
func (nc *NomadClient) SubmitJob(ctx context.Context, jobSpec string) (*cicd.NomadJobStatus, error) {
	url := fmt.Sprintf("%s/v1/jobs", nc.config.Address)

	headers := map[string]string{
		"Content-Type": "application/json",
	}

	if nc.config.Token != "" {
		headers["X-Nomad-Token"] = nc.config.Token
	}

	resp, err := nc.httpClient.Post(ctx, url, headers, []byte(jobSpec))
	if err != nil {
		return nil, fmt.Errorf("failed to submit Nomad job: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Nomad API returned status %d: %s", resp.StatusCode, string(resp.Body))
	}

	// Parse response to get job status
	status := &cicd.NomadJobStatus{
		ID:      "job-id", // Would parse from response
		Status:  "running",
		Running: 1,
		Desired: 1,
		Failed:  0,
	}

	return status, nil
}

// GetJobStatus implements cicd.NomadClient interface
func (nc *NomadClient) GetJobStatus(ctx context.Context, jobID string) (*cicd.NomadJobStatus, error) {
	url := fmt.Sprintf("%s/v1/job/%s", nc.config.Address, jobID)

	headers := map[string]string{
		"Accept": "application/json",
	}

	if nc.config.Token != "" {
		headers["X-Nomad-Token"] = nc.config.Token
	}

	resp, err := nc.httpClient.Get(ctx, url, headers)
	if err != nil {
		return nil, fmt.Errorf("failed to get Nomad job status: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Nomad API returned status %d", resp.StatusCode)
	}

	// Parse job status (simplified)
	status := &cicd.NomadJobStatus{
		ID:      jobID,
		Status:  "running",
		Running: 1,
		Desired: 1,
		Failed:  0,
	}

	return status, nil
}

// StopJob implements cicd.NomadClient interface
func (nc *NomadClient) StopJob(ctx context.Context, jobID string, purge bool) error {
	url := fmt.Sprintf("%s/v1/job/%s", nc.config.Address, jobID)
	if purge {
		url += "?purge=true"
	}

	headers := map[string]string{
		"Content-Type": "application/json",
	}

	if nc.config.Token != "" {
		headers["X-Nomad-Token"] = nc.config.Token
	}

	resp, err := nc.httpClient.Delete(ctx, url, headers)
	if err != nil {
		return fmt.Errorf("failed to stop Nomad job: %w", err)
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("Nomad API returned status %d: %s", resp.StatusCode, string(resp.Body))
	}

	return nil
}

// GetAllocations implements cicd.NomadClient interface
func (nc *NomadClient) GetAllocations(ctx context.Context, jobID string) ([]*cicd.NomadAllocation, error) {
	url := fmt.Sprintf("%s/v1/job/%s/allocations", nc.config.Address, jobID)

	headers := map[string]string{
		"Accept": "application/json",
	}

	if nc.config.Token != "" {
		headers["X-Nomad-Token"] = nc.config.Token
	}

	resp, err := nc.httpClient.Get(ctx, url, headers)
	if err != nil {
		return nil, fmt.Errorf("failed to get Nomad allocations: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Nomad API returned status %d", resp.StatusCode)
	}

	// Parse allocations (simplified)
	allocations := []*cicd.NomadAllocation{
		{
			ID:     "alloc-id",
			JobID:  jobID,
			Status: "running",
			NodeID: "node-id",
			Tasks:  map[string]string{"web": "running"},
		},
	}

	return allocations, nil
}

// NewVaultClient creates a new Vault client
func NewVaultClient(config VaultClientConfig, httpClient HTTPClient) (*VaultClient, error) {
	return &VaultClient{
		config:     config,
		httpClient: httpClient,
	}, nil
}

// ReadSecret implements cicd.VaultClient interface
func (vc *VaultClient) ReadSecret(ctx context.Context, path string) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/v1/%s", vc.config.Address, path)

	headers := map[string]string{
		"Accept": "application/json",
	}

	if vc.config.Token != "" {
		headers["X-Vault-Token"] = vc.config.Token
	}

	resp, err := vc.httpClient.Get(ctx, url, headers)
	if err != nil {
		return nil, fmt.Errorf("failed to read Vault secret: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Vault API returned status %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse Vault response: %w", err)
	}

	return result, nil
}

// WriteSecret implements cicd.VaultClient interface
func (vc *VaultClient) WriteSecret(ctx context.Context, path string, data map[string]interface{}) error {
	url := fmt.Sprintf("%s/v1/%s", vc.config.Address, path)

	reqBody, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal secret data: %w", err)
	}

	headers := map[string]string{
		"Content-Type": "application/json",
	}

	if vc.config.Token != "" {
		headers["X-Vault-Token"] = vc.config.Token
	}

	resp, err := vc.httpClient.Post(ctx, url, headers, reqBody)
	if err != nil {
		return fmt.Errorf("failed to write Vault secret: %w", err)
	}

	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return fmt.Errorf("Vault API returned status %d: %s", resp.StatusCode, string(resp.Body))
	}

	return nil
}

// DeleteSecret implements cicd.VaultClient interface
func (vc *VaultClient) DeleteSecret(ctx context.Context, path string) error {
	url := fmt.Sprintf("%s/v1/%s", vc.config.Address, path)

	headers := map[string]string{}

	if vc.config.Token != "" {
		headers["X-Vault-Token"] = vc.config.Token
	}

	resp, err := vc.httpClient.Delete(ctx, url, headers)
	if err != nil {
		return fmt.Errorf("failed to delete Vault secret: %w", err)
	}

	if resp.StatusCode != 204 {
		return fmt.Errorf("Vault API returned status %d: %s", resp.StatusCode, string(resp.Body))
	}

	return nil
}

// ListSecrets implements cicd.VaultClient interface
func (vc *VaultClient) ListSecrets(ctx context.Context, path string) ([]string, error) {
	url := fmt.Sprintf("%s/v1/%s?list=true", vc.config.Address, path)

	headers := map[string]string{
		"Accept": "application/json",
	}

	if vc.config.Token != "" {
		headers["X-Vault-Token"] = vc.config.Token
	}

	resp, err := vc.httpClient.Get(ctx, url, headers)
	if err != nil {
		return nil, fmt.Errorf("failed to list Vault secrets: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Vault API returned status %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse Vault response: %w", err)
	}

	// Parse keys from response (simplified)
	keys := []string{"key1", "key2"} // Would parse from actual response

	return keys, nil
}

// NewConsulClient creates a new Consul client
func NewConsulClient(config ConsulClientConfig, httpClient HTTPClient) (*ConsulClient, error) {
	return &ConsulClient{
		config:     config,
		httpClient: httpClient,
	}, nil
}

// GetKV implements cicd.ConsulClient interface
func (cc *ConsulClient) GetKV(ctx context.Context, key string) (string, error) {
	url := fmt.Sprintf("http://%s/v1/kv/%s", cc.config.Address, key)

	headers := map[string]string{
		"Accept": "application/json",
	}

	if cc.config.Token != "" {
		headers["X-Consul-Token"] = cc.config.Token
	}

	resp, err := cc.httpClient.Get(ctx, url, headers)
	if err != nil {
		return "", fmt.Errorf("failed to get Consul KV: %w", err)
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("Consul API returned status %d", resp.StatusCode)
	}

	var kvPairs []ConsulKVPair
	if err := json.Unmarshal(resp.Body, &kvPairs); err != nil {
		return "", fmt.Errorf("failed to parse Consul response: %w", err)
	}

	if len(kvPairs) == 0 {
		return "", fmt.Errorf("key not found")
	}

	return kvPairs[0].Value, nil
}

// PutKV implements cicd.ConsulClient interface
func (cc *ConsulClient) PutKV(ctx context.Context, key, value string) error {
	url := fmt.Sprintf("http://%s/v1/kv/%s", cc.config.Address, key)

	headers := map[string]string{
		"Content-Type": "application/octet-stream",
	}

	if cc.config.Token != "" {
		headers["X-Consul-Token"] = cc.config.Token
	}

	resp, err := cc.httpClient.Put(ctx, url, headers, []byte(value))
	if err != nil {
		return fmt.Errorf("failed to put Consul KV: %w", err)
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("Consul API returned status %d: %s", resp.StatusCode, string(resp.Body))
	}

	return nil
}

// DeleteKV implements cicd.ConsulClient interface
func (cc *ConsulClient) DeleteKV(ctx context.Context, key string) error {
	url := fmt.Sprintf("http://%s/v1/kv/%s", cc.config.Address, key)

	headers := map[string]string{}

	if cc.config.Token != "" {
		headers["X-Consul-Token"] = cc.config.Token
	}

	resp, err := cc.httpClient.Delete(ctx, url, headers)
	if err != nil {
		return fmt.Errorf("failed to delete Consul KV: %w", err)
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("Consul API returned status %d: %s", resp.StatusCode, string(resp.Body))
	}

	return nil
}

// RegisterService implements cicd.ConsulClient interface
func (cc *ConsulClient) RegisterService(ctx context.Context, service *cicd.ConsulService) error {
	url := fmt.Sprintf("http://%s/v1/agent/service/register", cc.config.Address)

	reqBody, err := json.Marshal(service)
	if err != nil {
		return fmt.Errorf("failed to marshal service registration: %w", err)
	}

	headers := map[string]string{
		"Content-Type": "application/json",
	}

	if cc.config.Token != "" {
		headers["X-Consul-Token"] = cc.config.Token
	}

	resp, err := cc.httpClient.Put(ctx, url, headers, reqBody)
	if err != nil {
		return fmt.Errorf("failed to register Consul service: %w", err)
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("Consul API returned status %d: %s", resp.StatusCode, string(resp.Body))
	}

	return nil
}

// DeregisterService implements cicd.ConsulClient interface
func (cc *ConsulClient) DeregisterService(ctx context.Context, serviceID string) error {
	url := fmt.Sprintf("http://%s/v1/agent/service/deregister/%s", cc.config.Address, serviceID)

	headers := map[string]string{}

	if cc.config.Token != "" {
		headers["X-Consul-Token"] = cc.config.Token
	}

	resp, err := cc.httpClient.Put(ctx, url, headers, nil)
	if err != nil {
		return fmt.Errorf("failed to deregister Consul service: %w", err)
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("Consul API returned status %d: %s", resp.StatusCode, string(resp.Body))
	}

	return nil
}

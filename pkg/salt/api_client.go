package salt

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// APIClient provides all Salt operations through the REST API
// This is the unified interface that replaces salt-call, salt-run, salt-key, etc.
type APIClient struct {
	*Client
	logger otelzap.LoggerWithCtx
}

// NewAPIClient creates a new API-only Salt client
func NewAPIClient(rc *eos_io.RuntimeContext, config ClientConfig) (*APIClient, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Ensure we have valid API configuration
	if config.BaseURL == "" {
		return nil, fmt.Errorf("Salt API URL is required")
	}
	if config.Username == "" || config.Password == "" {
		return nil, fmt.Errorf("Salt API credentials are required")
	}
	
	// Set defaults if not provided
	if config.Logger == nil {
		config.Logger = logger.ZapLogger()
	}
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Minute
	}
	
	baseClient, err := NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Salt API client: %w", err)
	}
	
	return &APIClient{
		Client: baseClient,
		logger: logger,
	}, nil
}

// StateApplyLocal applies a state locally (replaces salt-call --local state.apply)
func (c *APIClient) StateApplyLocal(ctx context.Context, state string, pillar map[string]interface{}) (*StateResult, error) {
	c.logger.Info("Applying state locally via API",
		zap.String("state", state))
	
	// For local state apply, we target the minion itself
	// The API will handle local execution when appropriate
	return c.ExecuteStateApply(ctx, state, pillar, func(progress StateProgress) {
		c.logger.Info("State progress",
			zap.String("state", progress.State),
			zap.Bool("completed", progress.Completed),
			zap.Bool("success", progress.Success),
			zap.String("message", progress.Message))
	})
}

// CmdRunLocal runs a command locally (replaces salt-call --local cmd.run)
func (c *APIClient) CmdRunLocal(ctx context.Context, command string) (string, error) {
	c.logger.Debug("Running command locally via API",
		zap.String("command", command))
	
	hostname, err := c.getLocalHostname(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get local hostname: %w", err)
	}
	
	cmd := Command{
		Client:   "local",
		Target:   hostname,
		Function: "cmd.run",
		Args:     []string{command},
	}
	
	result, err := c.ExecuteCommand(ctx, cmd)
	if err != nil {
		return "", err
	}
	
	// Extract output from result
	if output, ok := result.Raw[hostname].(string); ok {
		return output, nil
	}
	
	return "", fmt.Errorf("unexpected response format")
}

// TestPing tests connectivity to minions (replaces salt '*' test.ping)
func (c *APIClient) TestPing(ctx context.Context, target string) (map[string]bool, error) {
	c.logger.Debug("Testing ping to minions",
		zap.String("target", target))
	
	cmd := Command{
		Client:   "local",
		Target:   target,
		Function: "test.ping",
	}
	
	result, err := c.ExecuteCommand(ctx, cmd)
	if err != nil {
		return nil, err
	}
	
	// Convert result to map[string]bool
	pingResults := make(map[string]bool)
	for minion, response := range result.Raw {
		if response == true {
			pingResults[minion] = true
		} else {
			pingResults[minion] = false
		}
	}
	
	return pingResults, nil
}

// GetGrains retrieves grain values (replaces salt '*' grains.get)
func (c *APIClient) GetGrains(ctx context.Context, target string, grains []string) (map[string]interface{}, error) {
	c.logger.Debug("Getting grains",
		zap.String("target", target),
		zap.Strings("grains", grains))
	
	cmd := Command{
		Client:   "local",
		Target:   target,
		Function: "grains.items",
	}
	
	if len(grains) > 0 {
		cmd.Function = "grains.get"
		cmd.Args = grains
	}
	
	result, err := c.ExecuteCommand(ctx, cmd)
	if err != nil {
		return nil, err
	}
	
	return result.Raw, nil
}

// ListKeys lists Salt keys (replaces salt-key -L)
func (c *APIClient) ListKeys(ctx context.Context) (*KeyList, error) {
	c.logger.Debug("Listing Salt keys")
	
	cmd := Command{
		Client:   "wheel",
		Function: "key.list_all",
	}
	
	result, err := c.ExecuteCommand(ctx, cmd)
	if err != nil {
		return nil, err
	}
	
	// Parse the response into KeyList structure
	keyList := &KeyList{}
	if data, ok := result.Raw["data"].(map[string]interface{}); ok {
		if ret, ok := data["return"].(map[string]interface{}); ok {
			keyList.Minions = extractStringSlice(ret["minions"])
			keyList.MinionsPre = extractStringSlice(ret["minions_pre"])
			keyList.MinionsRejected = extractStringSlice(ret["minions_rejected"])
			keyList.MinionsDenied = extractStringSlice(ret["minions_denied"])
		}
	}
	
	return keyList, nil
}

// AcceptKey accepts a minion key (replaces salt-key -a)
func (c *APIClient) AcceptKey(ctx context.Context, minion string) error {
	c.logger.Info("Accepting minion key",
		zap.String("minion", minion))
	
	cmd := Command{
		Client:   "wheel",
		Function: "key.accept",
		Kwargs: map[string]string{
			"match": minion,
		},
	}
	
	_, err := c.ExecuteCommand(ctx, cmd)
	return err
}

// DeleteKey deletes a minion key (replaces salt-key -d)
func (c *APIClient) DeleteKey(ctx context.Context, minion string) error {
	c.logger.Info("Deleting minion key",
		zap.String("minion", minion))
	
	cmd := Command{
		Client:   "wheel",
		Function: "key.delete",
		Kwargs: map[string]string{
			"match": minion,
		},
	}
	
	_, err := c.ExecuteCommand(ctx, cmd)
	return err
}

// RejectKey rejects a minion key (replaces salt-key -r)
func (c *APIClient) RejectKey(ctx context.Context, minion string) error {
	c.logger.Info("Rejecting minion key",
		zap.String("minion", minion))
	
	cmd := Command{
		Client:   "wheel",
		Function: "key.reject",
		Kwargs: map[string]string{
			"match": minion,
		},
	}
	
	_, err := c.ExecuteCommand(ctx, cmd)
	return err
}

// RunnerExecute executes a Salt runner (replaces salt-run)
func (c *APIClient) RunnerExecute(ctx context.Context, function string, args map[string]interface{}) (*CommandResult, error) {
	c.logger.Debug("Executing Salt runner",
		zap.String("function", function))
	
	// Convert args to kwargs format
	kwargs := make(map[string]string)
	for k, v := range args {
		kwargs[k] = fmt.Sprintf("%v", v)
	}
	
	cmd := Command{
		Client:   "runner",
		Function: function,
		Kwargs:   kwargs,
	}
	
	return c.ExecuteCommand(ctx, cmd)
}

// ManageUp lists responsive minions (replaces salt-run manage.up)
func (c *APIClient) ManageUp(ctx context.Context) ([]string, error) {
	result, err := c.RunnerExecute(ctx, "manage.up", nil)
	if err != nil {
		return nil, err
	}
	
	// Extract minion list from result
	if minions, ok := result.Raw["return"].([]interface{}); ok {
		var minionList []string
		for _, m := range minions {
			if minion, ok := m.(string); ok {
				minionList = append(minionList, minion)
			}
		}
		return minionList, nil
	}
	
	return nil, fmt.Errorf("unexpected response format")
}

// ManageDown lists unresponsive minions (replaces salt-run manage.down)
func (c *APIClient) ManageDown(ctx context.Context) ([]string, error) {
	result, err := c.RunnerExecute(ctx, "manage.down", nil)
	if err != nil {
		return nil, err
	}
	
	// Extract minion list from result
	if minions, ok := result.Raw["return"].([]interface{}); ok {
		var minionList []string
		for _, m := range minions {
			if minion, ok := m.(string); ok {
				minionList = append(minionList, minion)
			}
		}
		return minionList, nil
	}
	
	return nil, fmt.Errorf("unexpected response format")
}

// JobsActive lists active jobs (replaces salt-run jobs.active)
func (c *APIClient) JobsActive(ctx context.Context) (map[string]JobInfo, error) {
	result, err := c.RunnerExecute(ctx, "jobs.active", nil)
	if err != nil {
		return nil, err
	}
	
	jobs := make(map[string]JobInfo)
	if jobData, ok := result.Raw["return"].(map[string]interface{}); ok {
		for jobID, data := range jobData {
			if jobMap, ok := data.(map[string]interface{}); ok {
				job := JobInfo{
					ID:       jobID,
					Function: getString(jobMap, "Function"),
					Target:   getString(jobMap, "Target"),
					User:     getString(jobMap, "User"),
					StartTime: getString(jobMap, "StartTime"),
				}
				jobs[jobID] = job
			}
		}
	}
	
	return jobs, nil
}

// HighstateApply applies highstate (replaces salt '*' state.highstate)
func (c *APIClient) HighstateApply(ctx context.Context, target string, progress func(StateProgress)) (*StateResult, error) {
	c.logger.Info("Applying highstate",
		zap.String("target", target))
	
	// Start async job
	jobID, err := c.startHighstateJob(ctx, target)
	if err != nil {
		return nil, err
	}
	
	// Stream progress
	return c.streamJobProgress(ctx, jobID, progress)
}

// FileManage manages files via Salt (replaces file.managed state)
func (c *APIClient) FileManage(ctx context.Context, target, path, contents string, mode string) error {
	cmd := Command{
		Client:   "local",
		Target:   target,
		Function: "file.write",
		Args:     []string{path, contents},
	}
	
	if _, err := c.ExecuteCommand(ctx, cmd); err != nil {
		return err
	}
	
	// Set permissions if specified
	if mode != "" {
		modeCmd := Command{
			Client:   "local",
			Target:   target,
			Function: "file.set_mode",
			Args:     []string{path, mode},
		}
		
		if _, err := c.ExecuteCommand(ctx, modeCmd); err != nil {
			return err
		}
	}
	
	return nil
}

// ServiceManage manages services (replaces service.running state)
func (c *APIClient) ServiceManage(ctx context.Context, target, service, action string) error {
	var function string
	switch action {
	case "start":
		function = "service.start"
	case "stop":
		function = "service.stop"
	case "restart":
		function = "service.restart"
	case "reload":
		function = "service.reload"
	case "enable":
		function = "service.enable"
	case "disable":
		function = "service.disable"
	default:
		return fmt.Errorf("unknown service action: %s", action)
	}
	
	cmd := Command{
		Client:   "local",
		Target:   target,
		Function: function,
		Args:     []string{service},
	}
	
	_, err := c.ExecuteCommand(ctx, cmd)
	return err
}

// PkgInstall installs packages (replaces pkg.installed state)
func (c *APIClient) PkgInstall(ctx context.Context, target string, packages []string) error {
	cmd := Command{
		Client:   "local",
		Target:   target,
		Function: "pkg.install",
		Args:     packages,
	}
	
	_, err := c.ExecuteCommand(ctx, cmd)
	return err
}

// Helper functions

func (c *APIClient) getLocalHostname(ctx context.Context) (string, error) {
	// Get local minion ID via grains
	cmd := Command{
		Client:   "local",
		Target:   "*",
		Function: "grains.get",
		Args:     []string{"id"},
	}
	
	result, err := c.ExecuteCommand(ctx, cmd)
	if err != nil {
		return "", err
	}
	
	// Return first minion ID (should be local)
	for minion := range result.Raw {
		return minion, nil
	}
	
	return "", fmt.Errorf("no local minion found")
}

func (c *APIClient) startHighstateJob(ctx context.Context, target string) (string, error) {
	data := map[string][]string{
		"client": {"local_async"},
		"tgt":    {target},
		"fun":    {"state.highstate"},
	}
	
	// Use the existing client's HTTP methods
	resp, err := c.executeRawRequest(ctx, "POST", "", data)
	if err != nil {
		return "", err
	}
	
	var result struct {
		Return []struct {
			JID string `json:"jid"`
		} `json:"return"`
	}
	
	if err := json.Unmarshal(resp, &result); err != nil {
		return "", err
	}
	
	if len(result.Return) == 0 || result.Return[0].JID == "" {
		return "", fmt.Errorf("no job ID returned")
	}
	
	return result.Return[0].JID, nil
}

// executeRawRequest is a helper for custom API calls
func (c *APIClient) executeRawRequest(ctx context.Context, method, endpoint string, data interface{}) ([]byte, error) {
	// This would use the underlying HTTP client from the base Client
	// Implementation depends on the base Client's internal structure
	return nil, fmt.Errorf("not implemented - use ExecuteCommand instead")
}

// Utility functions

func extractStringSlice(data interface{}) []string {
	var result []string
	if slice, ok := data.([]interface{}); ok {
		for _, item := range slice {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
	}
	return result
}

func getString(m map[string]interface{}, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}

// KeyList represents the Salt key list
type KeyList struct {
	Minions         []string
	MinionsPre      []string
	MinionsRejected []string
	MinionsDenied   []string
}

// JobInfo represents job information
type JobInfo struct {
	ID        string
	Function  string
	Target    string
	User      string
	StartTime string
	Arguments []string
}
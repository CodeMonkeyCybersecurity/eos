# Cobra Command Functions to Convert to Variables

This document lists all functions that return `*cobra.Command` and need to be converted from function form to variable form.

## Summary
Total files with functions to convert: 31
Total functions to convert: 75

## Files and Functions by Directory

### cmd/backup/
**file.go** (4 functions):
- `newFileCmd()`
- `newFileBackupCmd()`
- `newFileListCmd()`
- `newFileRestoreCmd()`

### cmd/create/
**credentials.go** (3 functions):
- `CreateCredentialsCmd()`
- `newGenerateCredentialsCmd()`
- `newRevokeCredentialsCmd()`

**delphi.go** (3 functions):
- `newDockerDeployCmd()`
- `newCredentialsCmd()`
- `newCleanupCmd()`

**delphi_pipeline_webhook.go** (1 function):
- `NewDelphiWebhookCmd()`

**hecate_dns.go** (1 function):
- `NewCreateHetznerWildcardCmd()`

**jenkins.go** (1 function):
- `NewDeployJenkinsCmd()`

**kvm_install.go** (1 function):
- `NewKvmInstallCmd()`

**kvm_template.go** (1 function):
- `NewKvmTemplateCmd()`

**kvm_tenant.go** (1 function):
- `NewKvmTenantCmd()`

**pipeline_prompts.go** (1 function):
- `NewCreateCmd()`

### cmd/delete/
**pipeline_prompts.go** (1 function):
- `NewDeleteCmd()`

**pipeline_servies.go** (1 function):
- `DeletePipelineServices()`

### cmd/list/
**containers.go** (1 function):
- `ListContainers()`

**delphi-servicesstatus.go** (1 function):
- `NewStatusCmd()`

**delphi.go** (2 functions):
- `CheckPipeline()`
- `NewConfigCmd()`

**delphi_pipeline_prompts.go** (1 function):
- `NewValidateCmd()`

**list-delphi-services.go** (1 function):
- `NewListCmd()`

### cmd/read/
**analyze-ab-results.go** (1 function):
- `NewAnalyzeABResultsCmd()`

**delphi.go** (3 functions):
- `NewInspectCmd()`
- `NewPipelineFunctionalityCmd()`
- `NewVerifyPipelineSchemaCmd()`

**delphi_agents.go** (1 function):
- `NewAgentsCmd()`

**delphi_dashboard.go** (1 function):
- `NewDashboardCmd()`

**monitor-delphi.go** (1 function):
- `NewMonitorCmd()`

**pipeline.go** (1 function):
- `NewAllCmd()`

**pipeline_alerts.go** (1 function):
- `NewAlertsCmd()`

**pipeline_prompts.go** (1 function):
- `NewReadCmd()`

**pipeline_services.go** (1 function):
- `ReadPipelinePrompts()`

### cmd/self/
**integration_test.go** (2 functions):
- `createMockBackupRunCommand()`
- `createMockUserCreateCommand()`

**secrets.go** (6 functions):
- `NewSecretsCmd()`
- `NewSecretsConfigureCmd()`
- `NewSecretsSetCmd()`
- `NewSecretsTestCmd()`
- `NewSecretsStatusCmd()`
- `NewSecretsGetCmd()`

### cmd/self/git/
**commit.go** (1 function):
- `newCommitCmd()`

**config.go** (1 function):
- `newConfigCmd()`

**deploy.go** (1 function):
- `newDeployCmd()`

**info.go** (1 function):
- `newInfoCmd()`

**init.go** (1 function):
- `newInitCmd()`

**remote.go** (6 functions):
- `newRemoteCmd()`
- `newRemoteListCmd()`
- `newRemoteAddCmd()`
- `newRemoteSetURLCmd()`
- `newRemoteRemoveCmd()`
- `newRemoteRenameCmd()`

**status.go** (1 function):
- `newStatusCmd()`

### cmd/update/
**ab_config.go** (8 functions):
- `NewABConfigCmd()`
- `NewABConfigCreateCmd()`
- `NewABConfigStatusCmd()`
- `NewABConfigListCmd()`
- `NewABConfigEnableCmd()`
- `NewABConfigDisableCmd()`
- `NewABConfigAnalyzeCmd()`
- `NewABConfigValidateCmd()`

**authz.go** (3 functions):
- `NewPermissionsCmd()`
- `NewPermissionsCheckCmd()`
- `NewPermissionsFixCmd()`

**pipeline_prompts.go** (1 function):
- `NewUpdateCmd()`

**services.go** (7 functions):
- `NewServicesCmd()`
- `NewServicesListCmd()`
- `NewServicesStartCmd()`
- `NewServicesStopCmd()`
- `NewServicesRestartCmd()`
- `NewServicesStatusCmd()`
- `NewServicesLogsCmd()`

## Conversion Pattern

Functions should be converted from:
```go
func NewXxxCmd() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "xxx",
        Short: "Description",
    }
    return cmd
}
```

To:
```go
var xxxCmd = &cobra.Command{
    Use:   "xxx",
    Short: "Description",
}
```

## Notes
- Test files (integration_test.go) may not need conversion if they're only used in tests
- Some functions follow different naming patterns (e.g., `CreateCredentialsCmd()` vs `NewXxxCmd()`)
- The `cmd/self/git/` directory has consistent lowercase naming (`newXxxCmd()`)
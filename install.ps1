#Requires -Version 5.1
# install.ps1 - Windows installer for Eos CLI
# Last Updated: 2026-03-14
#
# Usage:
#   .\install.ps1                    # Standard install
#   .\install.ps1 -SkipBuild         # Install pre-built binary only
#   .\install.ps1 -Verbose           # Verbose output
#   Get-Help .\install.ps1           # Show help
#
# NOTE: Windows builds are limited to non-CGO features.
#       Libvirt (KVM) and Ceph support require Linux.
#       See install.sh for full-featured Linux installation.
#
# Exit codes:
#   0 - Success
#   1 - General failure
#   2 - Prerequisites not met
#   3 - Build failure
#   4 - Installation failure

[CmdletBinding()]
param(
    [switch]$SkipBuild,
    [switch]$Force
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# --- Constants (single source of truth) ---
$script:EosBinaryName  = "eos.exe"
$script:MinGoVersion   = [version]"1.25.6"
$script:MinBinarySizeBytes = 1048576  # 1 MB - same threshold as install.sh
$script:Component      = "install.ps1"

# --- Paths ---
$script:ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Definition
$script:EosBuildPath = Join-Path $script:ScriptDir $script:EosBinaryName
$script:InstallDir  = Join-Path $Env:ProgramFiles "eos"
$script:InstallPath = Join-Path $script:InstallDir $script:EosBinaryName
$script:SecretsDir  = Join-Path $Env:APPDATA "eos\Secrets"
$script:ConfigDir   = Join-Path $Env:APPDATA "eos\Config"
$script:LogDir      = Join-Path $Env:APPDATA "eos\Logs"

# ============================================================
# Logging - structured, PS 5.1 compatible, matches install.sh
# ============================================================

function Write-Log {
    <#
    .SYNOPSIS
        Structured log output matching install.sh format.
    .DESCRIPTION
        Outputs ISO 8601 timestamped, levelled, machine-parseable log lines.
        Format: YYYY-MM-DDTHH:MM:SSZ level=LEVEL component=install.ps1 msg="MESSAGE"
    #>
    param(
        [Parameter(Mandatory)]
        [ValidateSet("INFO","WARN","ERR","DEBUG")]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Message
    )

    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $line = '{0} level={1} component={2} msg="{3}"' -f $timestamp, $Level, $script:Component, $Message

    switch ($Level) {
        "ERR"  { Write-Host $line -ForegroundColor Red }
        "WARN" { Write-Host $line -ForegroundColor Yellow }
        "DEBUG" {
            if ($VerbosePreference -eq "Continue") {
                Write-Host $line -ForegroundColor Gray
            }
        }
        default { Write-Host $line -ForegroundColor Green }
    }
}

# ============================================================
# Prerequisites
# ============================================================

function Assert-Administrator {
    <#
    .SYNOPSIS
        Verify script is running with administrator privileges.
    .DESCRIPTION
        Writing to Program Files requires elevation. Fail early with
        clear remediation rather than cryptic access-denied errors.
    #>
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Write-Log ERR "Administrator privileges required"
        Write-Log ERR "Remediation: Right-click PowerShell and select 'Run as Administrator'"
        Write-Log ERR "Or run: Start-Process powershell -Verb RunAs -ArgumentList '-File', '$($MyInvocation.ScriptName)'"
        exit 2
    }
    Write-Log DEBUG "Running with administrator privileges"
}

function Find-GoExecutable {
    <#
    .SYNOPSIS
        Locate Go executable with fallback paths.
    .DESCRIPTION
        Checks PATH first, then common installation locations.
        Returns the Go command object or exits with remediation.
    #>
    $goCmd = Get-Command go -ErrorAction SilentlyContinue
    if ($goCmd) {
        Write-Log DEBUG "Go found in PATH: $($goCmd.Source)"
        return $goCmd
    }

    # Fallback locations (ordered by likelihood)
    $fallbackPaths = @(
        "$Env:ProgramFiles\Go\bin\go.exe",
        "$HOME\go\bin\go.exe",
        "C:\Go\bin\go.exe"
    )

    foreach ($path in $fallbackPaths) {
        if (Test-Path $path) {
            $parentDir = Split-Path $path
            $env:PATH = "$parentDir;$env:PATH"
            Write-Log INFO "Go found at fallback path: $path"
            return Get-Command go -ErrorAction SilentlyContinue
        }
    }

    Write-Log ERR "Go not found in PATH or standard locations"
    Write-Log ERR "Remediation: Install Go $($script:MinGoVersion) or later from https://go.dev/dl/"
    Write-Log ERR "After installing, ensure Go is in your PATH and restart PowerShell"
    exit 2
}

function Assert-GoVersion {
    <#
    .SYNOPSIS
        Validate Go version meets minimum requirement.
    .DESCRIPTION
        Parses 'go version' output and compares against MinGoVersion.
        Matches install.sh GO_VERSION pin behaviour.
    #>
    param([Parameter(Mandatory)] $GoCommand)

    $versionOutput = & $GoCommand.Source version 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Log ERR "Failed to get Go version: $versionOutput"
        exit 2
    }

    # Parse version string: "go version go1.25.6 windows/amd64"
    if ($versionOutput -match 'go(\d+\.\d+\.?\d*)') {
        $currentVersion = [version]$Matches[1]
        Write-Log INFO "Go version detected: $currentVersion (minimum: $($script:MinGoVersion))"

        if ($currentVersion -lt $script:MinGoVersion) {
            Write-Log ERR "Go version $currentVersion is below minimum $($script:MinGoVersion)"
            Write-Log ERR "Remediation: Update Go from https://go.dev/dl/"
            exit 2
        }
    }
    else {
        Write-Log WARN "Could not parse Go version from: $versionOutput"
        Write-Log WARN "Continuing with unverified Go version"
    }
}

function Show-FeatureLimitations {
    <#
    .SYNOPSIS
        Inform user about Windows build limitations.
    .DESCRIPTION
        Eos requires CGO for libvirt (KVM) and Ceph features.
        Windows builds are compiled without CGO, so these features
        are unavailable. This is informed consent per human-centric design.
    #>
    Write-Log WARN "Windows builds do not include CGO-dependent features:"
    Write-Log WARN "  - KVM/libvirt virtualisation management"
    Write-Log WARN "  - Ceph storage management (librados, librbd, libcephfs)"
    Write-Log WARN "For full features, use install.sh on a Linux system"
}

# ============================================================
# Build
# ============================================================

function Invoke-EosBuild {
    <#
    .SYNOPSIS
        Build Eos binary with validation.
    .DESCRIPTION
        Builds using package-level target (.) not main.go, matching
        install.sh and Go best practices. Validates output exists,
        meets minimum size, and passes smoke test.
    #>
    Write-Log INFO "Building Eos (CGO_ENABLED=0, Windows)..."

    try {
        Push-Location $script:ScriptDir

        # Clean previous build artifact
        if (Test-Path $script:EosBinaryName) {
            Remove-Item $script:EosBinaryName -Force
            Write-Log DEBUG "Removed previous build artifact"
        }

        # Build using package target (not main.go) per Go best practices
        # CGO_ENABLED=0 because Windows lacks libvirt/Ceph libraries
        $env:CGO_ENABLED = "0"
        $env:GO111MODULE = "on"
        $buildOutput = & go build -o $script:EosBinaryName . 2>&1
        $buildExitCode = $LASTEXITCODE

        if ($buildExitCode -ne 0) {
            Write-Log ERR "Build failed (exit code: $buildExitCode)"
            Write-Log ERR "Build output: $buildOutput"
            Write-Log ERR "Remediation: Check Go setup with 'go env' and resolve compilation errors"
            exit 3
        }

        # Validate binary exists
        if (-not (Test-Path $script:EosBinaryName)) {
            Write-Log ERR "Build reported success but binary was not created"
            exit 3
        }

        # Validate binary size (must be > 1MB, matching install.sh)
        $binarySize = (Get-Item $script:EosBinaryName).Length
        if ($binarySize -lt $script:MinBinarySizeBytes) {
            Write-Log ERR "Binary is suspiciously small: $binarySize bytes (minimum: $($script:MinBinarySizeBytes))"
            Write-Log ERR "This may indicate a failed or incomplete build"
            exit 3
        }
        Write-Log INFO "Build successful, binary size: $binarySize bytes"

        # Smoke test: verify binary executes
        $helpOutput = & ".\$($script:EosBinaryName)" --help 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log ERR "Binary smoke test failed (--help returned exit code $LASTEXITCODE)"
            Write-Log ERR "Output: $helpOutput"
            exit 3
        }
        Write-Log INFO "Binary smoke test passed (--help)"
    }
    finally {
        Pop-Location
    }
}

# ============================================================
# Hash verification
# ============================================================

function Get-FileSHA256 {
    <#
    .SYNOPSIS
        Compute SHA256 hash using .NET (locale-independent).
    .DESCRIPTION
        Uses .NET Get-FileHash (locale-independent) instead of external
        hash tools that produce locale-dependent output on non-English Windows.
    #>
    param([Parameter(Mandatory)] [string]$Path)

    if (-not (Test-Path $Path)) {
        return $null
    }

    # Get-FileHash is available in PS 5.1+
    $hash = (Get-FileHash -Path $Path -Algorithm SHA256).Hash
    return $hash.ToLower()
}

function Compare-BinaryHashes {
    <#
    .SYNOPSIS
        Compare existing and new binary hashes for change detection.
    .DESCRIPTION
        Logs both hashes for audit trail. Warns if hashes are identical
        (no-op install). This is actual verification, not display-only.
    #>
    $existingHash = Get-FileSHA256 -Path $script:InstallPath
    $newHash = Get-FileSHA256 -Path $script:EosBuildPath

    if ($existingHash) {
        Write-Log INFO "Existing binary SHA256: $existingHash"
    }
    else {
        Write-Log INFO "No existing binary at $($script:InstallPath) (fresh install)"
    }

    if ($newHash) {
        Write-Log INFO "New binary SHA256: $newHash"
    }

    if ($existingHash -and $newHash -and ($existingHash -eq $newHash)) {
        if (-not $Force) {
            Write-Log WARN "New binary is identical to existing binary (same SHA256)"
            Write-Log WARN "Use -Force to reinstall anyway"
            Write-Log INFO "Installation skipped (no changes)"
            exit 0
        }
        Write-Log WARN "Reinstalling identical binary (-Force specified)"
    }
}

# ============================================================
# Backup and Install
# ============================================================

function Backup-ExistingBinary {
    <#
    .SYNOPSIS
        Create timestamped backup of existing binary before overwrite.
    .DESCRIPTION
        Matching install.sh backup_existing_binary() pattern.
        Provides rollback capability if new binary is broken.
    #>
    if (Test-Path $script:InstallPath) {
        $timestamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
        $backupPath = "$($script:InstallPath).backup.$timestamp"
        Copy-Item -Path $script:InstallPath -Destination $backupPath -Force
        Write-Log INFO "Backed up existing binary to: $backupPath"
    }
    else {
        Write-Log DEBUG "No existing binary to back up"
    }
}

function Install-EosBinary {
    <#
    .SYNOPSIS
        Copy built binary to install directory.
    .DESCRIPTION
        Creates install directory if needed, copies binary,
        and verifies the installed copy matches the build output.
    #>
    Write-Log INFO "Installing to $($script:InstallPath)"

    # Ensure install directory exists
    if (-not (Test-Path $script:InstallDir)) {
        New-Item -ItemType Directory -Force -Path $script:InstallDir | Out-Null
        Write-Log DEBUG "Created install directory: $($script:InstallDir)"
    }

    # Copy binary
    Copy-Item -Force $script:EosBuildPath $script:InstallPath

    # Verify copy integrity
    $sourceHash = Get-FileSHA256 -Path $script:EosBuildPath
    $destHash = Get-FileSHA256 -Path $script:InstallPath
    if ($sourceHash -ne $destHash) {
        Write-Log ERR "Post-copy integrity check failed"
        Write-Log ERR "Source SHA256: $sourceHash"
        Write-Log ERR "Dest SHA256:   $destHash"
        Write-Log ERR "Remediation: Check disk health and available space"
        exit 4
    }
    Write-Log DEBUG "Post-copy integrity verified (SHA256 match)"
}

# ============================================================
# Directory creation and PATH
# ============================================================

function Initialize-AppDirectories {
    <#
    .SYNOPSIS
        Create application directories idempotently.
    .DESCRIPTION
        Creates Secrets, Config, and Logs directories under %APPDATA%\eos.
        Check-before-act pattern for idempotency.
    #>
    Write-Log INFO "Ensuring application directories exist"

    foreach ($dir in @($script:SecretsDir, $script:ConfigDir, $script:LogDir)) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Force -Path $dir | Out-Null
            Write-Log DEBUG "Created directory: $dir"
        }
        else {
            Write-Log DEBUG "Directory already exists: $dir"
        }
    }
}

function Update-UserPath {
    <#
    .SYNOPSIS
        Add eos install directory to user PATH idempotently.
    .DESCRIPTION
        Modifies the persistent user PATH environment variable.
        Check-before-act pattern prevents duplicate entries.
    #>
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not $currentPath) {
        $currentPath = ""
    }

    if ($currentPath -notlike "*$($script:InstallDir)*") {
        try {
            [Environment]::SetEnvironmentVariable("Path", "$currentPath;$($script:InstallDir)", "User")
            Write-Log INFO "Added eos directory to user PATH: $($script:InstallDir)"
            Write-Log INFO "Restart PowerShell for PATH changes to take effect"
        }
        catch {
            Write-Log WARN "Failed to update user PATH: $($_.Exception.Message)"
            Write-Log WARN "Remediation: Manually add '$($script:InstallDir)' to your PATH"
        }
    }
    else {
        Write-Log DEBUG "eos directory already in user PATH"
    }
}

# ============================================================
# Main
# ============================================================

function Main {
    Write-Log INFO "Eos Windows installer starting"
    Write-Log INFO "Script directory: $($script:ScriptDir)"

    # --- Prerequisites ---
    Assert-Administrator
    Show-FeatureLimitations

    $goCmd = Find-GoExecutable
    Assert-GoVersion -GoCommand $goCmd

    # --- Build ---
    if (-not $SkipBuild) {
        Invoke-EosBuild
    }
    else {
        Write-Log INFO "Skipping build (-SkipBuild specified)"
        if (-not (Test-Path $script:EosBuildPath)) {
            Write-Log ERR "No pre-built binary found at: $($script:EosBuildPath)"
            Write-Log ERR "Remediation: Build first with 'go build -o $($script:EosBinaryName) .' or remove -SkipBuild flag"
            exit 3
        }
    }

    # --- Hash comparison and change detection ---
    Compare-BinaryHashes

    # --- Backup and install ---
    Backup-ExistingBinary
    Install-EosBinary

    # --- Directories and PATH ---
    Initialize-AppDirectories
    Update-UserPath

    # --- Summary ---
    Write-Log INFO "Eos installation complete on Windows"
    Write-Log INFO "Binary installed to: $($script:InstallPath)"
    Write-Log INFO "Run: eos.exe --help"
    Write-Log WARN "Note: Some commands require Linux. See install.sh for full-featured deployment."
}

# Entry point with top-level error handling
try {
    Main
}
catch {
    Write-Log ERR "Installation failed: $($_.Exception.Message)"
    Write-Log ERR "Location: $($_.InvocationInfo.ScriptName):$($_.InvocationInfo.ScriptLineNumber)"
    Write-Log ERR "Remediation: Review the error above, fix the issue, and re-run"
    exit 1
}

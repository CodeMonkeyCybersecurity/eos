# Install-eos.ps1
$ErrorActionPreference = "Stop"

function Log {
    param ([string]$Level, [string]$Message)
    $color = if ($Level -eq "ERR") { "Red" } elseif ($Level -eq "WARN") { "Yellow" } else { "Green" }
    Write-Host "[$Level] $Message" -ForegroundColor $color
}

# Globals
$EosBinaryName = "eos.exe"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$EosBuildPath = Join-Path $ScriptDir $EosBinaryName
$InstallDir = Join-Path $Env:ProgramFiles "eos"
$InstallPath = Join-Path $InstallDir $EosBinaryName
$SecretsDir = Join-Path $Env:APPDATA "eos\Secrets"
$ConfigDir  = Join-Path $Env:APPDATA "eos\Config"
$LogDir     = Join-Path $Env:APPDATA "eos\Logs"

# --- Check Go ---
$GoCmd = Get-Command go -ErrorAction SilentlyContinue
if (-not $GoCmd) {
    $Fallback = "$HOME\go\bin\go.exe"
    if (Test-Path $Fallback) {
        $env:PATH = "$($Fallback | Split-Path);$env:PATH"
        Log INFO "🧩 Using fallback Go: $Fallback"
    } else {
        Log ERR "❌ Go not found in PATH. Install from https://go.dev/dl/"
        exit 1
    }
}

# --- Build ---
Log INFO "📦 Building Eos..."
try {
    Push-Location $ScriptDir
    if (Test-Path $EosBinaryName) { Remove-Item $EosBinaryName -Force }
    & go build -o $EosBinaryName main.go
    if ($LASTEXITCODE -ne 0) {
        Log ERR "❌ Build failed. Check your Go setup."
        exit 1
    }
} finally {
    Pop-Location
}

# --- Hash Check ---
function Show-Hash($Label, $Path) {
    if (Test-Path $Path) {
        Log INFO "$Label"
        & CertUtil -hashfile $Path SHA256 | Select-String -NotMatch "hash of file|CertUtil|SHA256" | ForEach-Object { "    $_" }
    }
}

Show-Hash "🔍 Existing binary SHA256:" $InstallPath

# --- Install Binary ---
Log INFO "🚚 Installing to $InstallPath"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Force $EosBuildPath $InstallPath

Show-Hash "🔍 New binary SHA256:" $InstallPath

# --- Create Directories ---
Log INFO "📁 Ensuring application directories"
foreach ($dir in @($SecretsDir, $ConfigDir, $LogDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
}

# --- Update PATH (user) ---
$PathUser = [Environment]::GetEnvironmentVariable("Path", "User")
if ($PathUser -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$PathUser;$InstallDir", "User")
    Log INFO "📎 Added eos directory to user PATH"
} else {
    Log INFO "✅ eos directory already in user PATH"
}

# --- Complete ---
Log INFO ""
Log INFO "🎉 eos installation complete on Windows"
Log INFO "👉 Run: eos.exe --help"
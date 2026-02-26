<#
.SYNOPSIS
  Softy Installer for Windows

.DESCRIPTION
  Run from an elevated PowerShell prompt:

    irm https://raw.githubusercontent.com/ash-rain/softy/main/install.ps1 | iex

  Or with a custom install directory:

    $env:SOFTY_DIR = "C:\softy"
    irm https://raw.githubusercontent.com/ash-rain/softy/main/install.ps1 | iex
#>
#Requires -Version 5.1
$ErrorActionPreference = 'Stop'

$Repo       = 'https://github.com/ash-rain/softy.git'
$InstallDir = if ($env:SOFTY_DIR) { $env:SOFTY_DIR } else { "$HOME\softy" }
$Branch     = if ($env:SOFTY_BRANCH) { $env:SOFTY_BRANCH } else { 'main' }

# ── Helpers ───────────────────────────────────────────────────────────────

function Info  { param($msg) Write-Host "[softy] $msg" -ForegroundColor Cyan }
function Ok    { param($msg) Write-Host "[softy] $msg" -ForegroundColor Green }
function Warn  { param($msg) Write-Host "[softy] $msg" -ForegroundColor Yellow }
function Fail  { param($msg) Write-Host "[softy] $msg" -ForegroundColor Red; exit 1 }

function Need {
  param($cmd, $hint)
  if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
    Fail "Required: '$cmd' is not installed. $hint"
  }
}

function VersionGe {
  param($v1, $v2)
  try {
    $a = [version]($v1 -replace '-.*$','' -replace '[^0-9.]','')
    $b = [version]$v2
    return $a -ge $b
  } catch { return $false }
}

# ── Platform check ────────────────────────────────────────────────────────

if ($env:OS -ne 'Windows_NT') {
  Fail "This script is for Windows. On macOS/Linux run: curl -fsSL https://raw.githubusercontent.com/ash-rain/softy/main/install.sh | bash"
}

Info "Detected Windows $([System.Environment]::OSVersion.Version)"

# ── Prerequisites ─────────────────────────────────────────────────────────

Info "Checking prerequisites..."

Need git    "Install: https://git-scm.com/download/win"
Need node   "Install Node.js >= 18: https://nodejs.org"
Need npm    "Comes with Node.js"
Need docker "Install Docker Desktop: https://www.docker.com/products/docker-desktop"

$nodeVer = (node -v) -replace '^v',''
if (-not (VersionGe $nodeVer '18.0')) {
  Fail "Node.js >= 18 required (found v$nodeVer)"
}
Ok "Node.js v$nodeVer"

try {
  docker info 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) { throw }
} catch {
  Fail "Docker daemon is not running. Start Docker Desktop and try again."
}
Ok "Docker is running"

# ── Clone / Update ────────────────────────────────────────────────────────

if (Test-Path (Join-Path $InstallDir '.git')) {
  Info "Existing install found at $InstallDir — pulling latest..."
  git -C $InstallDir fetch origin
  git -C $InstallDir reset --hard "origin/$Branch"
} else {
  Info "Cloning softy into $InstallDir..."
  git clone --depth 1 --branch $Branch $Repo $InstallDir
}

Set-Location $InstallDir

# ── Node dependencies ─────────────────────────────────────────────────────

Info "Installing Node dependencies..."
$npmResult = npm ci --prefer-offline 2>&1
if ($LASTEXITCODE -ne 0) {
  npm install
}

# ── Work directories ──────────────────────────────────────────────────────

New-Item -ItemType Directory -Force "$HOME\.softy\work"            | Out-Null
New-Item -ItemType Directory -Force "$HOME\.softy\ghidra-projects" | Out-Null
Ok "Created ~\.softy\work and ~\.softy\ghidra-projects"

# ── Docker backend ────────────────────────────────────────────────────────

Info "Building Docker backend (this may take a few minutes on first run)..."
docker compose -f docker/docker-compose.yml build
if ($LASTEXITCODE -ne 0) { Fail "Docker build failed." }

Info "Starting backend container..."
docker compose -f docker/docker-compose.yml up -d
if ($LASTEXITCODE -ne 0) { Fail "Docker up failed." }

# Wait for health
Info "Waiting for backend to become healthy..."
$tries = 0
$max   = 30
$healthy = $false
while ($tries -lt $max) {
  try {
    $resp = Invoke-WebRequest 'http://localhost:7800/health' -UseBasicParsing -TimeoutSec 1 -EA Stop
    if ($resp.StatusCode -eq 200) { $healthy = $true; break }
  } catch {}
  Start-Sleep 1
  $tries++
}

if ($healthy) {
  Ok "Backend is healthy on port 7800"
} else {
  Warn "Backend not healthy after ${max}s. Check: docker logs softy-tools"
}

# ── Build Electron app ────────────────────────────────────────────────────

Info "Building Electron app..."
npx electron-vite build
if ($LASTEXITCODE -ne 0) { Fail "Electron build failed." }

# ── Done ──────────────────────────────────────────────────────────────────

Write-Host ""
Ok "Softy installed successfully!"
Write-Host ""
Info "  Location:  $InstallDir"
Info "  Backend:   http://localhost:7800/health"
Write-Host ""
Info "Quick start:"
Info "  cd $InstallDir"
Info "  npm run dev          # dev mode with hot-reload"
Info "  npm run build        # production build"
Write-Host ""
Info "Docker lifecycle:"
Info "  npm run docker:up    # start backend"
Info "  npm run docker:down  # stop backend"
Info "  npm run docker:logs  # view logs"
Write-Host ""

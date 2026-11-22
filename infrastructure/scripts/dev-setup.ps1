# PowerShell local development environment setup script for DCMP
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "DCMP Local Development Setup (Windows PowerShell)" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

# 1. Check Node.js
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Error "Node.js (>=20) is required but not found in PATH. Install via: winget install OpenJS.NodeJS.LTS"
    exit 1
}

# 2. Check or install pnpm
if (-not (Get-Command pnpm -ErrorAction SilentlyContinue)) {
    Write-Host "Installing pnpm globally via npm..." -ForegroundColor Yellow
    npm install -g pnpm@9
}

# 3. Check Java JDK 17
if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
    Write-Warning "Java JDK 17 not found in PATH. Required for Android builds. Install via: winget install Microsoft.OpenJDK.17"
}

# 4. Create .env from .env.example (if missing)
if (-not (Test-Path ".env")) {
    Write-Host "Creating .env from .env.example..." -ForegroundColor Green
    Copy-Item ".env.example" ".env"
}

# 5. Install pnpm workspace packages & build shared libraries
Write-Host "Installing monorepo dependencies with pnpm..." -ForegroundColor Green
pnpm install --frozen-lockfile

Write-Host "Building shared workspace packages..." -ForegroundColor Green
pnpm run build:packages

# 6. Flutter setup
$flutterCmd = Get-Command flutter -ErrorAction SilentlyContinue
if (-not $flutterCmd -and (Test-Path "C:\flutter\bin\flutter.bat")) {
    $flutterCmd = "C:\flutter\bin\flutter.bat"
    Write-Host "Found Flutter at C:\flutter\bin. Consider adding it to your user PATH." -ForegroundColor Yellow
}

if ($flutterCmd) {
    Write-Host "Installing Flutter dependencies..." -ForegroundColor Green
    Push-Location apps/mobile-app
    & $flutterCmd pub get
    Pop-Location
} else {
    Write-Warning "Flutter CLI not found in PATH or at C:\flutter\bin. Flutter dependencies skipped."
}

# 7. Docker infrastructure
if (Get-Command docker -ErrorAction SilentlyContinue) {
    Write-Host "Starting Docker Compose infrastructure (PostgreSQL & Redis)..." -ForegroundColor Green
    docker compose up -d
} else {
    Write-Warning "Docker CLI not found in PATH. Install Docker Desktop via: winget install Docker.DockerDesktop"
}

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "DCMP setup complete! Run 'pnpm run build' to compile all apps." -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Cyan

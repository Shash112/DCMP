# PowerShell local development environment setup script for DCMP
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "DCMP Local Development Setup (Windows PowerShell)" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

# 1. Check Node.js
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Error "Node.js (>=20) is required but not found in PATH."
    exit 1
}

# 2. Check or install pnpm
if (-not (Get-Command pnpm -ErrorAction SilentlyContinue)) {
    Write-Host "Installing pnpm globally via npm..." -ForegroundColor Yellow
    npm install -g pnpm@9
}

# 3. Create .env from .env.example
if (-not (Test-Path ".env")) {
    Write-Host "Creating .env from .env.example..." -ForegroundColor Green
    Copy-Item ".env.example" ".env"
}

# 4. Install pnpm workspace packages
Write-Host "Installing monorepo dependencies with pnpm..." -ForegroundColor Green
pnpm install

# 5. Flutter setup
if (Get-Command flutter -ErrorAction SilentlyContinue) {
    Write-Host "Installing Flutter dependencies..." -ForegroundColor Green
    Push-Location apps/mobile-app
    flutter pub get
    Pop-Location
} else {
    Write-Warning "Flutter CLI not found in PATH. Flutter dependencies skipped."
}

# 6. Docker infrastructure
if (Get-Command docker -ErrorAction SilentlyContinue) {
    Write-Host "Starting Docker Compose infrastructure (PostgreSQL & Redis)..." -ForegroundColor Green
    docker compose up -d
} else {
    Write-Warning "Docker CLI not found in PATH. Docker containers could not be launched automatically."
}

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "DCMP setup complete! Run 'pnpm build' to compile." -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Cyan

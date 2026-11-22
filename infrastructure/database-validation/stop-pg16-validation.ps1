# Stop disposable PostgreSQL 16 validation cluster. Optionally wipe data with -Wipe.
param([switch]$Wipe)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$PgRoot = (Get-Content (Join-Path $Root '.tools\pgroot.txt') -ErrorAction SilentlyContinue)
if (-not $PgRoot) { $PgRoot = Join-Path $Root '.tools\pgsql16\pgsql' }
$Bin = Join-Path $PgRoot 'bin'
$Data = Join-Path $Root 'data\pgdata'

if (Test-Path $Data) {
  & (Join-Path $Bin 'pg_ctl.exe') -D $Data status 2>$null | Out-Null
  if ($LASTEXITCODE -eq 0) {
    Write-Host 'Stopping PostgreSQL...'
    & (Join-Path $Bin 'pg_ctl.exe') -D $Data stop -m fast | Out-Host
  }
}
if ($Wipe) {
  Write-Host 'Wiping validation data directory...'
  Remove-Item -Recurse -Force (Join-Path $Root 'data') -ErrorAction SilentlyContinue
}
Write-Host 'Cleanup complete (binaries retained under .tools/; use -Wipe to remove data only).'
Write-Host 'Docker alternative: docker compose -f infrastructure/docker/docker-compose.pg16-validation.yml down -v'

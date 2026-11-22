# Start disposable PostgreSQL 16.10 validation cluster (local binaries; not Docker).
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$PgRoot = Get-Content (Join-Path $Root '.tools\pgroot.txt') -ErrorAction SilentlyContinue
if (-not $PgRoot) {
  $PgRoot = Join-Path $Root '.tools\pgsql16\pgsql'
}
$Bin = Join-Path $PgRoot 'bin'
$Data = Join-Path $Root 'data\pgdata'
$Log = Join-Path $Root 'evidence\postgres.log'
$Port = 55432
$Pass = 'dcmp_val_only_not_prod'

New-Item -ItemType Directory -Force -Path (Split-Path $Log), $Data | Out-Null

if (-not (Test-Path (Join-Path $Data 'PG_VERSION'))) {
  Write-Host "initdb $Data"
  $env:TZ = 'UTC'
  & (Join-Path $Bin 'initdb.exe') -D $Data -U dcmp_val_super -A trust --locale=C --encoding=UTF8 | Out-Host
  Add-Content (Join-Path $Data 'postgresql.conf') @"

# DCMP validation overrides
port = $Port
listen_addresses = '127.0.0.1'
max_connections = 40
shared_buffers = 128MB
logging_collector = off
"@
  Set-Content (Join-Path $Data 'pg_hba.conf') @"
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             all                                     trust
host    all             all             127.0.0.1/32            trust
host    all             all             ::1/128                 trust
"@
}

# Stop if already running on this data dir
& (Join-Path $Bin 'pg_ctl.exe') -D $Data status 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) {
  Write-Host 'PostgreSQL already running'
} else {
  Write-Host "Starting PostgreSQL 16 on 127.0.0.1:$Port"
  & (Join-Path $Bin 'pg_ctl.exe') -D $Data -l $Log -o "-p $Port" start | Out-Host
  Start-Sleep -Seconds 2
}

# Use cmd to avoid PowerShell treating psql stderr/progress as terminating errors
$ver = cmd /c "`"$(Join-Path $Bin 'psql.exe')`" -h 127.0.0.1 -p $Port -U dcmp_val_super -d postgres -Atc `"SELECT version();`" 2>&1"
Write-Host $ver

# Ensure database exists
$dbExists = cmd /c "`"$(Join-Path $Bin 'psql.exe')`" -h 127.0.0.1 -p $Port -U dcmp_val_super -d postgres -Atc `"SELECT 1 FROM pg_database WHERE datname='dcmp_validation'`" 2>&1"
if ($dbExists -ne '1') {
  cmd /c "`"$(Join-Path $Bin 'psql.exe')`" -h 127.0.0.1 -p $Port -U dcmp_val_super -d postgres -c `"CREATE DATABASE dcmp_validation OWNER dcmp_val_super;`" 2>&1" | Out-Host
}

# Write connection env for runners (not a production secret)
@"
PGHOST=127.0.0.1
PGPORT=$Port
PGUSER=dcmp_val_super
PGDATABASE=dcmp_validation
PGROOT=$PgRoot
"@ | Set-Content (Join-Path $Root '.env.validation') -Encoding utf8

Write-Host 'Validation cluster ready.'
Write-Host "Connection: host=127.0.0.1 port=$Port db=dcmp_validation user=dcmp_val_super"

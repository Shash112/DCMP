$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
& (Join-Path $Root 'start-pg16-validation.ps1')
Get-Content (Join-Path $Root '.env.validation') | ForEach-Object {
  if ($_ -match '^(.*?)=(.*)$') { Set-Item -Path "env:$($matches[1])" -Value $matches[2] }
}
$PgRoot = $env:PGROOT
$Psql = Join-Path $PgRoot 'bin\psql.exe'
$Evidence = Join-Path $Root 'evidence'
New-Item -ItemType Directory -Force -Path $Evidence | Out-Null
$Log = Join-Path $Evidence 'sql-apply.log'
Remove-Item $Log -ErrorAction SilentlyContinue

$scripts = @(
  '00_create_roles_and_schemas.sql',
  '01_create_foundation_tables.sql',
  '02_create_identity_and_session_tables.sql',
  '03_create_refresh_idempotency.sql',
  '04_create_security_support_tables.sql',
  '05_apply_rls_policies.sql',
  '06_create_security_functions.sql',
  '07_apply_grants_and_triggers.sql',
  '08_validate_catalog.sql',
  '09_auth_gateway_persistence.sql',
  '10_login_identity_resolution.sql'
)

foreach ($s in $scripts) {
  $path = Join-Path $Root "sql\$s"
  Write-Host "Applying $s ..."
  $out = & $Psql -h $env:PGHOST -p $env:PGPORT -U $env:PGUSER -d $env:PGDATABASE -v ON_ERROR_STOP=1 -f $path 2>&1
  $out | Tee-Object -FilePath $Log -Append | Out-Host
  if ($LASTEXITCODE -ne 0) {
    throw "SQL failed: $s (exit $LASTEXITCODE)"
  }
}
Write-Host 'All SQL scripts applied successfully.'

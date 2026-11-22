# Phase 2.1.18 — Full schema validation runner (PostgreSQL 16.10 only)
# Creates/uses disposable DB dcmp_full_schema_validation. Never drops automatically. Never touches PG18.
$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
& (Join-Path $Root 'start-pg16-validation.ps1')
Get-Content (Join-Path $Root '.env.validation') | ForEach-Object {
  if ($_ -match '^(.*?)=(.*)$') { Set-Item -Path "env:$($matches[1])" -Value $matches[2] }
}
$Psql = Join-Path $env:PGROOT 'bin\psql.exe'
$Evidence = Join-Path $Root 'evidence\phase-2.1.18'
New-Item -ItemType Directory -Force -Path $Evidence | Out-Null
$TargetDb = 'dcmp_full_schema_validation'
$Port = [int]$env:PGPORT

if ($Port -ne 55432) { throw "Refusing non-validation port $Port (expected 55432)" }

function Invoke-PsqlFile {
  param([string]$Database, [string]$FilePath)
  $arg = "-h $($env:PGHOST) -p $($env:PGPORT) -U $($env:PGUSER) -d $Database -v ON_ERROR_STOP=1 -f `"$FilePath`""
  cmd /c "`"$Psql`" $arg > `"$env:TEMP\dcmp_psql_out.txt`" 2>&1"
  $code = $LASTEXITCODE
  $out = Get-Content "$env:TEMP\dcmp_psql_out.txt" -ErrorAction SilentlyContinue
  return @{ ExitCode = $code; Output = $out }
}

function Invoke-PsqlQuery {
  param([string]$Database, [string]$Sql)
  $escaped = $Sql -replace '"', '\"'
  cmd /c "`"$Psql`" -h $($env:PGHOST) -p $($env:PGPORT) -U $($env:PGUSER) -d $Database -Atc `"$escaped`" > `"$env:TEMP\dcmp_psql_q.txt`" 2>&1"
  $code = $LASTEXITCODE
  $out = @(Get-Content "$env:TEMP\dcmp_psql_q.txt" -ErrorAction SilentlyContinue)
  return @{ ExitCode = $code; Output = $out }
}

function Invoke-PsqlAt {
  param([string]$Database, [string]$Sql)
  $tmp = Join-Path $env:TEMP 'dcmp_psql_cmd.sql'
  Set-Content -Path $tmp -Value $Sql -Encoding utf8
  return Invoke-PsqlFile -Database $Database -FilePath $tmp
}

$verRes = Invoke-PsqlQuery -Database postgres -Sql 'SELECT version();'
$ver = ($verRes.Output | Where-Object { $_ -match 'PostgreSQL' } | Select-Object -Last 1)
if ($ver -notmatch 'PostgreSQL 16\.10') { throw "Expected PostgreSQL 16.10, got: $($verRes.Output -join ' | ')" }
$ver | Set-Content (Join-Path $Evidence 'pg_version.txt')
Write-Host $ver

$existsRes = Invoke-PsqlQuery -Database postgres -Sql "SELECT 1 FROM pg_database WHERE datname='$TargetDb'"
$exists = ($existsRes.Output | Where-Object { $_.Trim() -eq '1' } | Select-Object -First 1)
$SkipMigrate = $false
if ($exists -eq '1') {
  Write-Host "Database $TargetDb already exists — will NOT drop automatically."
  $tblRes = Invoke-PsqlQuery -Database $TargetDb -Sql "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='r'"
  $tbl = ($tblRes.Output | Where-Object { $_.Trim() -match '^\d+$' } | Select-Object -Last 1)
  if (-not $tbl) { $tbl = '0' }
  Write-Host "Existing public tables: $tbl"
  if ([int]$tbl -ge 63) {
    Write-Host 'Schema appears already applied (>=63 tables). Skipping migrate; re-running catalog + tests only.'
    $SkipMigrate = $true
  } elseif ([int]$tbl -eq 0) {
    Write-Host 'Empty database — continuing migrations.'
  } else {
    throw "Database $TargetDb exists with incomplete schema ($tbl tables). Manual review required; refusing automatic drop."
  }
} else {
  Write-Host "Creating database $TargetDb"
  $r = Invoke-PsqlAt -Database postgres -Sql "CREATE DATABASE $TargetDb OWNER dcmp_val_super;"
  $r.Output | Out-Host
  if ($r.ExitCode -ne 0) { throw 'CREATE DATABASE failed' }
}

$env:PGDATABASE = $TargetDb
@"
PGHOST=$($env:PGHOST)
PGPORT=$($env:PGPORT)
PGDATABASE=$TargetDb
PGUSER=$($env:PGUSER)
"@ | Set-Content (Join-Path $Evidence 'target_db.txt')

$MigDir = Join-Path $Root 'full-schema\migrations'
$scripts = @(
  'S00_roles_and_schemas.sql',
  'S01_stage1_foundation.sql',
  'S02_stage2_licensing_devices.sql',
  'S03_stage3_checklists.sql',
  'S04_stage4_assignments.sql',
  'S05_stage5_inspections.sql',
  'S06_stage6_issues_sync.sql',
  'S07_stage7_notifications_support_audit.sql',
  'S08_apply_rls.sql',
  'S09_grants_and_auth_helpers.sql',
  'S10_catalog_validate.sql',
  'S11_security_gap_closure.sql',
  'S12_ssa_definer_policies.sql',
  'S13_ssa_b64url_pad.sql',
  'S14_prisma_compat_uniques.sql'
)

$migLog = Join-Path $Evidence 'migration_execution.log'
if (-not $SkipMigrate) {
  Remove-Item $migLog -ErrorAction SilentlyContinue
  foreach ($s in $scripts) {
    $path = Join-Path $MigDir $s
    $stamp = Get-Date -Format 'o'
    Write-Host "[$stamp] Applying $s ..."
    "==== $stamp $s ====" | Out-File -FilePath $migLog -Append -Encoding utf8
    $res = Invoke-PsqlFile -Database $TargetDb -FilePath $path
    $res.Output | Tee-Object -FilePath $migLog -Append | Out-Host
    if ($res.ExitCode -ne 0) { throw "Migration failed: $s (exit $($res.ExitCode))" }
  }
  Write-Host 'All migrations applied.'
} else {
  Write-Host 'Re-applying grants/security gap closures (S09–S14) on existing schema...'
  foreach ($s in @(
    'S09_grants_and_auth_helpers.sql',
    'S10_catalog_validate.sql',
    'S11_security_gap_closure.sql',
    'S12_ssa_definer_policies.sql',
    'S13_ssa_b64url_pad.sql',
    'S14_prisma_compat_uniques.sql'
  )) {
    $res = Invoke-PsqlFile -Database $TargetDb -FilePath (Join-Path $MigDir $s)
    $res.Output | Tee-Object -FilePath (Join-Path $Evidence 'catalog_revalidate.log') -Append | Out-Host
    if ($res.ExitCode -ne 0) { throw "Re-apply failed: $s (exit $($res.ExitCode))" }
  }
}

$snap = Invoke-PsqlAt -Database $TargetDb -Sql @"
SELECT count(*) AS public_tables FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='r';
SELECT count(*) AS fk_count FROM pg_constraint WHERE contype='f';
SELECT count(*) AS index_count FROM pg_indexes WHERE schemaname='public';
SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='public' AND c.relkind='r' AND c.relrowsecurity
ORDER BY 1;
SELECT rolname, rolsuper, rolbypassrls FROM pg_roles
WHERE rolname IN ('dcmp_app','dcmp_platform_admin','dcmp_audit_writer','dcmp_sec_definer','dcmp_cleanup','dcmp_migrator')
ORDER BY 1;
"@
$snap.Output | Tee-Object -FilePath (Join-Path $Evidence 'catalog_snapshot.txt') | Out-Host

$TestSql = Join-Path $Root 'full-schema\tests\db_sec_suite.sql'
if (Test-Path $TestSql) {
  Write-Host 'Running DB-SEC suite...'
  $tres = Invoke-PsqlFile -Database $TargetDb -FilePath $TestSql
  $tres.Output | Tee-Object -FilePath (Join-Path $Evidence 'db_sec_suite.log') | Out-Host
  if ($tres.ExitCode -ne 0) { throw "DB-SEC suite failed (exit $($tres.ExitCode))" }
}

Write-Host "Full schema validation complete for $TargetDb"

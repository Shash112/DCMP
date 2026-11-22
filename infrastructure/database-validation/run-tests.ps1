$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Get-Content (Join-Path $Root '.env.validation') | ForEach-Object {
  if ($_ -match '^(.*?)=(.*)$') { Set-Item -Path "env:$($matches[1])" -Value $matches[2] }
}
$Psql = Join-Path $env:PGROOT 'bin\psql.exe'
$Out = Join-Path $Root 'evidence\db-sec-results.out'
Write-Host 'Running DB-SEC suite...'
& $Psql -h $env:PGHOST -p $env:PGPORT -U $env:PGUSER -d $env:PGDATABASE -v ON_ERROR_STOP=0 -f (Join-Path $Root 'tests\run_db_sec_suite.sql') 2>&1 |
  Tee-Object -FilePath $Out | Out-Host
Write-Host "Results written to $Out"

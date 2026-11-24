param(
  [string]$BackupDir = ".\backups"
)

if (-not $env:DATABASE_URL) {
  throw "DATABASE_URL must be set"
}

New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$out = Join-Path $BackupDir "hawk_postgres_$stamp.dump"

pg_dump $env:DATABASE_URL --format=custom --file=$out
Write-Host "backup_created=$out"

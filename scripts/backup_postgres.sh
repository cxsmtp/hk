#!/usr/bin/env bash
set -euo pipefail

: "${DATABASE_URL:?DATABASE_URL must be set}"
BACKUP_DIR="${BACKUP_DIR:-./backups}"
mkdir -p "$BACKUP_DIR"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
out="$BACKUP_DIR/hawk_postgres_$stamp.dump"

pg_dump "$DATABASE_URL" --format=custom --file="$out"
chmod 600 "$out"
echo "backup_created=$out"

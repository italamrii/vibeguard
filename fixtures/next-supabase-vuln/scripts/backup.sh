#!/usr/bin/env bash
set -euo pipefail
# vg-expect: secrets/provider-key
pg_dump "postgresql://postgres.{{FAKE:supabase_ref:proj}}:{{FAKE:db_password:prod}}@aws-0-eu-central-1.pooler.supabase.com:5432/postgres" > backup.sql

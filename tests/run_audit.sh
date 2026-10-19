#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
docker compose exec -T camera python - < tests/test_audit.py
docker compose exec -T router python - < tests/test_router.py
sh tests/run_mfa.sh

#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
for service in camera nas laptop; do
    echo "Testing MFA: $service"
    docker compose exec -T "$service" python - < tests/test_mfa.py
done

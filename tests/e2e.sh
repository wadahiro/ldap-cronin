#!/bin/bash
# Start two fresh Samba4 ADs (ad-src / ad) and run the E2E tests.
set -euo pipefail
cd "$(dirname "$0")/.."

cleanup() { [ "${KEEP:-}" = 1 ] || docker compose --profile e2e down -v >/dev/null 2>&1; }
trap cleanup EXIT

docker compose --profile e2e down -v >/dev/null 2>&1 || true
docker compose --profile e2e up -d --build --wait
# Image for the lab E2E (a lab that runs with docker run only, without docker compose).
export E2E_LAB_IMAGE=ldap-cronin/samba-ad:e2e
docker build -q -t "$E2E_LAB_IMAGE" docker/ad >/dev/null
# Generic LDAP E2E: a throw-away OpenLDAP pair. Skipped (the test self-skips) when the image cannot be pulled.
export E2E_OPENLDAP_IMAGE="${E2E_OPENLDAP_IMAGE:-osixia/openldap:1.5.0}"
docker image inspect "$E2E_OPENLDAP_IMAGE" >/dev/null 2>&1 || docker pull -q "$E2E_OPENLDAP_IMAGE" >/dev/null 2>&1 || unset E2E_OPENLDAP_IMAGE
# Right after startup, LDAPS can be slow to begin accepting connections, so wait.
set -a; [ -f .env ] && . ./.env; set +a
go test -tags e2e -count=1 -v ./e2e/...

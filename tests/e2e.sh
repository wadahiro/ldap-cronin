#!/bin/bash
# Start two fresh Samba4 ADs (ad-src / ad), build the lab images, and run the E2E tests.
set -euo pipefail
cd "$(dirname "$0")/.."

cleanup() { [ "${KEEP:-}" = 1 ] || docker compose --profile e2e down -v >/dev/null 2>&1; }
trap cleanup EXIT

docker compose --profile e2e down -v >/dev/null 2>&1 || true
docker compose --profile e2e up -d --build --wait
# Image for the lab E2E (a lab that runs with docker run only, without docker compose).
export E2E_LAB_IMAGE=ldap-cronin/samba-ad:e2e
docker build -q -t "$E2E_LAB_IMAGE" docker/ad >/dev/null
# Generic LDAP E2E and the OpenLDAP lab: our own image (docker/ldap), so nothing is pulled.
export E2E_LDAP_IMAGE=ldap-cronin/openldap:e2e
docker build -q -t "$E2E_LDAP_IMAGE" docker/ldap >/dev/null
# Right after startup, LDAPS can be slow to begin accepting connections, so wait.
set -a; [ -f .env ] && . ./.env; set +a
go test -tags e2e -count=1 -v ./e2e/...

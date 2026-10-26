#!/usr/bin/env bash
# Entry point for air-gapped environments (no internet access; docker is available, docker compose is not needed).
# The real work is done by the `lab` subcommand of the bundled ldap-cronin. This script only picks the
# binary for the local architecture and hands everything over to it.
#
#   ./setup.sh                                  verify the package and load the images into docker; start nothing (lab load)
#   ./setup.sh up                               start a lab interactively, asking for the domain name and administrator password
#   ./setup.sh up --realm corp.example.local    start a lab with the given domain name
#   ./setup.sh up --profile ldap --suffix dc=example,dc=org   start an OpenLDAP lab instead
#   ./setup.sh status                           show the status
#   ./setup.sh snapshot [name]                  take a snapshot of the data
#   ./setup.sh snapshots                        list snapshots
#   ./setup.sh restore [name]                   roll back to a snapshot (choose from a list if the name is omitted)
#   ./setup.sh down                             stop (the data is kept)
#   ./setup.sh reset                            also delete the data (use this when changing the domain name)
#
# To clone, load the images, then make the lab with the source's domain (name, NetBIOS name, domain SID and GUID):
#   ./setup.sh && ./ldap-cronin lab up --config config.toml
# A lab started with "up" alone has a domain of its own, which clone refuses for that config; only reset undoes it.
# That is why setup.sh with no arguments starts nothing. The domain name is decided when the lab is created, not when
# the image is built.
# See `./setup.sh help` (= ldap-cronin lab help) and docs/lab.md for details.
#
# Written to also work with bash 3.x (macOS) and 4.2 (old RHEL).
set -euo pipefail
cd "$(dirname "$0")"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = Linux ] || die "the bundled binaries are for Linux (amd64 / arm64). On other OSes, build ldap-cronin and run 'ldap-cronin lab load --bundle-dir .'"

case "$(uname -m)" in
  x86_64|amd64)  arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) die "unsupported architecture: $(uname -m) (only amd64 / arm64)" ;;
esac

bin="bin/ldap-cronin-linux-${arch}"
[ -x "$bin" ] || [ -f "$bin" ] || die "$bin not found"
chmod +x "$bin"

# For convenience, also place it as ./ldap-cronin (so that clone / diff can be run directly).
cp "$bin" ./ldap-cronin && chmod +x ./ldap-cronin

# With no arguments, or flags of load first, load the images.
if [ $# -eq 0 ]; then
  exec ./ldap-cronin lab load
fi
case "$1" in
  -h|--help) exec ./ldap-cronin lab help ;;
  --reload|--reload=*|--skip-verify|--skip-verify=*|--bundle-dir|--bundle-dir=*) exec ./ldap-cronin lab load "$@" ;;
  -*) die "setup.sh with no command only loads the images; to start a lab, run: ./setup.sh up $*" ;;
esac
exec ./ldap-cronin lab "$@"

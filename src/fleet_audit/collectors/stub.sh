#!/usr/bin/env bash
set -euo pipefail

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# shellcheck source=common.sh
source "${script_directory}/common.sh"

workspace="${1-}"
fleet_audit_require_workspace "${workspace}"

umask 077
printf 'ready\n' >"${workspace}/stub.status"

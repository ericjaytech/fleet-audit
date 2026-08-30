#!/usr/bin/env bash
set -euo pipefail

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# shellcheck source=common.sh
source "${script_directory}/common.sh"

workspace="${1-}"
source_root="${2-/}"
fleet_audit_require_workspace "${workspace}"

cpuinfo="${source_root%/}/proc/cpuinfo"
meminfo="${source_root%/}/proc/meminfo"

if [[ ! -r "${cpuinfo}" ]]; then
    printf 'cpuinfo is unavailable.\n' >&2
    exit 10
fi
if [[ ! -r "${meminfo}" ]]; then
    printf 'meminfo is unavailable.\n' >&2
    exit 10
fi
if ! logical_processors="$(getconf _NPROCESSORS_ONLN)"; then
    printf 'logical processor count is unavailable.\n' >&2
    exit 10
fi
if [[ ! "${logical_processors}" =~ ^[1-9][0-9]*$ ]]; then
    printf 'logical processor count is invalid.\n' >&2
    exit 1
fi

umask 077
cp -- "${cpuinfo}" "${workspace}/cpuinfo"
cp -- "${meminfo}" "${workspace}/meminfo"
printf '%s\n' "${logical_processors}" >"${workspace}/logical-processors"

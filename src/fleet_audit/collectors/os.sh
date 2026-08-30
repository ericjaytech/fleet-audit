#!/usr/bin/env bash
set -euo pipefail

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# shellcheck source=common.sh
source "${script_directory}/common.sh"

workspace="${1-}"
source_root="${2-/}"
fleet_audit_require_workspace "${workspace}"

os_release="${source_root%/}/etc/os-release"
uptime="${source_root%/}/proc/uptime"

if [[ ! -r "${os_release}" ]]; then
    printf 'os-release is unavailable.\n' >&2
    exit 10
fi
if [[ ! -r "${uptime}" ]]; then
    printf 'uptime is unavailable.\n' >&2
    exit 10
fi

kernel="$(uname -r)"
architecture="$(uname -m)"
if [[ -z "${kernel}" || -z "${architecture}" ]]; then
    printf 'uname returned incomplete platform data.\n' >&2
    exit 1
fi

umask 077
cp -- "${os_release}" "${workspace}/os-release"
cp -- "${uptime}" "${workspace}/uptime"
printf '%s\n' "${kernel}" >"${workspace}/kernel"
printf '%s\n' "${architecture}" >"${workspace}/architecture"

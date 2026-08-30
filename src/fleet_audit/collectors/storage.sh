#!/usr/bin/env bash
set -euo pipefail

workspace="${1-}"
script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# shellcheck source=common.sh
source "${script_directory}/common.sh"

fleet_audit_require_workspace "${workspace}"
umask 077

lsblk_available=0
if lsblk --list --json --bytes --output NAME,TYPE,SIZE \
    >"${workspace}/lsblk.json" 2>/dev/null; then
    lsblk_available=1
else
    rm -- "${workspace}/lsblk.json"
    printf 'unavailable\n' >"${workspace}/lsblk.error"
fi

findmnt_available=0
if findmnt --df --list --json --bytes --output TARGET,FSTYPE,SIZE,USED,USE% \
    >"${workspace}/findmnt.json" 2>/dev/null; then
    findmnt_available=1
else
    rm -- "${workspace}/findmnt.json"
    printf 'unavailable\n' >"${workspace}/findmnt.error"
fi

if ((lsblk_available == 0 && findmnt_available == 0)); then
    exit 10
fi

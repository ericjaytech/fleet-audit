#!/usr/bin/env bash
set -euo pipefail

workspace="${1-}"
source_root="${2-/}"
script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# shellcheck source=common.sh
source "${script_directory}/common.sh"

fleet_audit_require_workspace "${workspace}"
umask 077

if dpkg-query -W '-f=${db:Status-Status}\t${Package}\t${Version}\t${Architecture}\n' \
    2>/dev/null | awk '
    BEGIN {
        OFS = "\t"
        installed = 0
        invalid = 0
    }
    NF == 0 { next }
    $1 == "installed" && NF == 4 {
        print $2, $3, $4
        installed++
        next
    }
    $1 == "installed" {
        invalid = 1
    }
    END {
        if (invalid || installed == 0) {
            exit 1
        }
    }
' >"${workspace}/packages.tsv"; then
    :
else
    rm -- "${workspace}/packages.tsv"
    printf 'unavailable\n' >"${workspace}/packages.error"
fi

if systemctl list-unit-files --type=service --no-legend --no-pager --plain \
    2>/dev/null | awk '
    BEGIN {
        invalid = 0
    }
    NF == 0 { next }
    NF < 2 || $1 !~ /\.service$/ {
        invalid = 1
        next
    }
    $2 == "enabled" || $2 == "enabled-runtime" {
        print $1
    }
    END {
        if (invalid) {
            exit 1
        }
    }
' >"${workspace}/services.txt"; then
    :
else
    rm -- "${workspace}/services.txt"
    printf 'unavailable\n' >"${workspace}/services.error"
fi

if apt-get --simulate -o Debug::NoLocking=1 upgrade 2>/dev/null | awk '
    BEGIN {
        pending = 0
    }
    /^Inst / {
        pending++
    }
    END {
        print pending
    }
' >"${workspace}/pending-updates.txt"; then
    :
else
    rm -- "${workspace}/pending-updates.txt"
    printf 'unavailable\n' >"${workspace}/pending-updates.error"
fi

if [[ -e "${source_root%/}/var/run/reboot-required" ]]; then
    printf 'true\n' >"${workspace}/reboot-required.txt"
else
    printf 'false\n' >"${workspace}/reboot-required.txt"
fi

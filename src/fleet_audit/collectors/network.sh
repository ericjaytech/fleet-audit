#!/usr/bin/env bash
set -euo pipefail

workspace="${1-}"
script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# shellcheck source=common.sh
source "${script_directory}/common.sh"

fleet_audit_require_workspace "${workspace}"
umask 077

interfaces_available=0
if ip -brief link show 2>/dev/null | awk '
    BEGIN { OFS = "\t" }
    NF >= 2 {
        state = tolower($2)
        if (state != "up" && state != "down") {
            state = "unknown"
        }
        print $1, state
    }
' >"${workspace}/interfaces.tsv"; then
    interfaces_available=1
else
    rm -- "${workspace}/interfaces.tsv"
    printf 'unavailable\n' >"${workspace}/interfaces.error"
fi

sockets_available=0
if ss -H -l -n -t -u 2>/dev/null | awk '
    BEGIN { OFS = "\t" }
    NF >= 5 {
        if ($1 ~ /^tcp/) {
            protocol = "tcp"
        } else if ($1 ~ /^udp/) {
            protocol = "udp"
        } else {
            next
        }

        endpoint = $5
        port = endpoint
        sub(/^.*:/, "", port)
        if (port !~ /^[0-9]+$/) {
            next
        }
        numeric_port = port + 0
        if (numeric_port < 1 || numeric_port > 65535) {
            next
        }

        address = endpoint
        sub(/:[^:]*$/, "", address)
        sub(/%.*/, "", address)
        if (address == "*" || address == "0.0.0.0" ||
            address == "::" || address == "[::]") {
            scope = "wildcard"
        } else if (address ~ /^127\./ || address == "::1" || address == "[::1]") {
            scope = "loopback"
        } else if (address == "") {
            scope = "unknown"
        } else {
            scope = "external"
        }
        print protocol, numeric_port, scope
    }
' >"${workspace}/sockets.tsv"; then
    sockets_available=1
else
    rm -- "${workspace}/sockets.tsv"
    printf 'unavailable\n' >"${workspace}/sockets.error"
fi

if ((interfaces_available == 0 && sockets_available == 0)); then
    exit 10
fi

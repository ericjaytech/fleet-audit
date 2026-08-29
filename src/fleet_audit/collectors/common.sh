#!/usr/bin/env bash

fleet_audit_require_workspace() {
    local workspace="${1-}"

    if [[ -z "${workspace}" || ! -d "${workspace}" || -L "${workspace}" ]]; then
        printf 'Collector workspace is not a private directory.\n' >&2
        return 2
    fi
}

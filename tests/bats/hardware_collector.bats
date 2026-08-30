#!/usr/bin/env bats

setup() {
    project_root="$(cd -- "${BATS_TEST_DIRNAME}/../.." && pwd -P)"
    test_root="$(mktemp -d)"
    source_root="${test_root}/source"
    workspace="${test_root}/workspace"
    mkdir -p -- "${source_root}/proc" "${workspace}"
    printf 'processor : 0\nmodel name : Test CPU\n' >"${source_root}/proc/cpuinfo"
    printf 'MemTotal: 1024 kB\n' >"${source_root}/proc/meminfo"
}

teardown() {
    rm -rf -- "${test_root}"
}

@test "hardware collector writes only expected raw files to its workspace" {
    source_before="$(find "${source_root}" -type f -exec sha256sum {} + | sort)"

    run /bin/bash "${project_root}/src/fleet_audit/collectors/hardware.sh" \
        "${workspace}" "${source_root}"

    [ "${status}" -eq 0 ]
    [ "${output}" = "" ]
    [ "$(find "${workspace}" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)" = \
        $'cpuinfo\nlogical-processors\nmeminfo' ]
    [ "$(find "${source_root}" -type f -exec sha256sum {} + | sort)" = "${source_before}" ]
    cmp "${source_root}/proc/cpuinfo" "${workspace}/cpuinfo"
    cmp "${source_root}/proc/meminfo" "${workspace}/meminfo"
    [[ "$(<"${workspace}/logical-processors")" =~ ^[1-9][0-9]*$ ]]
}

@test "hardware collector reports unavailable proc input without partial output" {
    rm -- "${source_root}/proc/meminfo"

    run /bin/bash "${project_root}/src/fleet_audit/collectors/hardware.sh" \
        "${workspace}" "${source_root}"

    [ "${status}" -eq 10 ]
    [[ "${output}" == *"meminfo is unavailable"* ]]
    [ -z "$(find "${workspace}" -mindepth 1 -maxdepth 1 -print -quit)" ]
}

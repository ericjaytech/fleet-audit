#!/usr/bin/env bats

setup() {
    project_root="$(cd -- "${BATS_TEST_DIRNAME}/../.." && pwd -P)"
    test_root="$(mktemp -d)"
    source_root="${test_root}/source"
    workspace="${test_root}/workspace"
    mkdir -p -- "${source_root}/etc" "${source_root}/proc" "${workspace}"
    printf '%s\n' 'ID=test' 'VERSION_ID="1.0"' 'PRETTY_NAME="Test Linux"' \
        >"${source_root}/etc/os-release"
    printf '123.45 678.90\n' >"${source_root}/proc/uptime"
}

teardown() {
    rm -rf -- "${test_root}"
}

@test "platform collector writes only expected raw files to its workspace" {
    source_before="$(find "${source_root}" -type f -exec sha256sum {} + | sort)"

    run /bin/bash "${project_root}/src/fleet_audit/collectors/os.sh" \
        "${workspace}" "${source_root}"

    [ "${status}" -eq 0 ]
    [ "${output}" = "" ]
    [ "$(find "${workspace}" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)" = \
        $'architecture\nkernel\nos-release\nuptime' ]
    [ "$(find "${source_root}" -type f -exec sha256sum {} + | sort)" = "${source_before}" ]
    cmp "${source_root}/etc/os-release" "${workspace}/os-release"
    cmp "${source_root}/proc/uptime" "${workspace}/uptime"
    [ -s "${workspace}/kernel" ]
    [ -s "${workspace}/architecture" ]
}

@test "platform collector reports unavailable os-release without writing output" {
    rm -- "${source_root}/etc/os-release"

    run /bin/bash "${project_root}/src/fleet_audit/collectors/os.sh" \
        "${workspace}" "${source_root}"

    [ "${status}" -eq 10 ]
    [[ "${output}" == *"os-release is unavailable"* ]]
    [ -z "$(find "${workspace}" -mindepth 1 -maxdepth 1 -print -quit)" ]
}

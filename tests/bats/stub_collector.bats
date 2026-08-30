#!/usr/bin/env bats

setup() {
    project_root="$(cd -- "${BATS_TEST_DIRNAME}/../.." && pwd -P)"
    test_root="$(mktemp -d)"
    workspace="${test_root}/workspace"
    mkdir -- "${workspace}"
}

teardown() {
    rm -rf -- "${test_root}"
}

@test "stub collector writes only its expected workspace file" {
    run /bin/bash "${project_root}/src/fleet_audit/collectors/stub.sh" "${workspace}"

    [ "${status}" -eq 0 ]
    [ "${output}" = "" ]
    [ "$(find "${workspace}" -mindepth 1 -maxdepth 1 -printf '%f\n')" = "stub.status" ]
    [ "$(<"${workspace}/stub.status")" = "ready" ]
}

@test "stub collector rejects a symlink workspace" {
    real_workspace="${test_root}/real-workspace"
    symlink_workspace="${test_root}/symlink-workspace"
    mkdir -- "${real_workspace}"
    ln -s -- "${real_workspace}" "${symlink_workspace}"

    run /bin/bash "${project_root}/src/fleet_audit/collectors/stub.sh" "${symlink_workspace}"

    [ "${status}" -eq 2 ]
    [[ "${output}" == *"Collector workspace is not a private directory."* ]]
    [ -z "$(find "${real_workspace}" -mindepth 1 -maxdepth 1 -print -quit)" ]
}

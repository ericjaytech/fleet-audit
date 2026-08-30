#!/usr/bin/env bats

setup() {
    project_root="$(cd -- "${BATS_TEST_DIRNAME}/../.." && pwd -P)"
    test_root="$(mktemp -d)"
    fake_bin="${test_root}/bin"
    workspace="${test_root}/workspace"
    mkdir -- "${fake_bin}" "${workspace}"

    printf '%s\n' '#!/usr/bin/env bash' \
        'printf '\''%s\n'\'' '\''{"blockdevices": [{"name": "sda", "type": "disk", "size": 1024}]}'\''' \
        >"${fake_bin}/lsblk"
    printf '%s\n' '#!/usr/bin/env bash' \
        'printf '\''%s\n'\'' '\''{"filesystems": [{"target": "/", "fstype": "ext4", "size": 1024, "used": 512, "use%": "50%"}]}'\''' \
        >"${fake_bin}/findmnt"
    chmod 0700 "${fake_bin}/lsblk" "${fake_bin}/findmnt"
}

teardown() {
    rm -rf -- "${test_root}"
}

@test "storage collector writes only explicit-column JSON to its workspace" {
    tools_before="$(find "${fake_bin}" -type f -exec sha256sum {} + | sort)"

    run env PATH="${fake_bin}:/usr/bin:/bin" /bin/bash \
        "${project_root}/src/fleet_audit/collectors/storage.sh" "${workspace}"

    [ "${status}" -eq 0 ]
    [ "${output}" = "" ]
    [ "$(find "${workspace}" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)" = \
        $'findmnt.json\nlsblk.json' ]
    [ "$(find "${fake_bin}" -type f -exec sha256sum {} + | sort)" = "${tools_before}" ]
    ! grep -Eqi 'serial|uuid|label' "${workspace}/lsblk.json" "${workspace}/findmnt.json"
}

@test "storage collector preserves filesystem output when lsblk is unsupported" {
    printf '%s\n' '#!/usr/bin/env bash' 'exit 1' >"${fake_bin}/lsblk"
    chmod 0700 "${fake_bin}/lsblk"

    run env PATH="${fake_bin}:/usr/bin:/bin" /bin/bash \
        "${project_root}/src/fleet_audit/collectors/storage.sh" "${workspace}"

    [ "${status}" -eq 0 ]
    [ "$(find "${workspace}" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)" = \
        $'findmnt.json\nlsblk.error' ]
    [ "$(<"${workspace}/lsblk.error")" = "unavailable" ]
}

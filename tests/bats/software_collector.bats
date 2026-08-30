#!/usr/bin/env bats

setup() {
    project_root="$(cd -- "${BATS_TEST_DIRNAME}/../.." && pwd -P)"
    test_root="$(mktemp -d)"
    fake_bin="${test_root}/bin"
    source_root="${test_root}/source"
    workspace="${test_root}/workspace"
    mkdir -p -- "${fake_bin}" "${source_root}/var/run" "${workspace}"

    printf '%s\n' '#!/usr/bin/env bash' \
        '[[ "$1" == "-W" ]] || exit 2' \
        '[[ "$2" == '\''-f=${db:Status-Status}\t${Package}\t${Version}\t${Architecture}\n'\'' ]] || exit 2' \
        'printf '\''%b'\'' '\''installed\tzlib1g\t1:1.2.13.dfsg-1\tamd64\nconfig-files\told-package\t1.0\tamd64\ninstalled\tacl\t2.3.1-3\tamd64\n'\''' \
        >"${fake_bin}/dpkg-query"
    printf '%s\n' '#!/usr/bin/env bash' \
        '[[ "$*" == "list-unit-files --type=service --no-legend --no-pager --plain" ]] || exit 2' \
        'printf '\''%s\n'\'' '\''ssh.service enabled enabled'\'' '\''cron.service enabled-runtime enabled'\'' '\''cups.service disabled enabled'\'' '\''dbus.service static -'\''' \
        >"${fake_bin}/systemctl"
    printf '%s\n' '#!/usr/bin/env bash' \
        '[[ "$*" == "--simulate -o Debug::NoLocking=1 upgrade" ]] || exit 2' \
        'printf '\''%s\n'\'' '\''Inst openssl [1.0] (1.1 Ubuntu:stable [amd64])'\'' '\''Conf openssl (1.1 Ubuntu:stable [amd64])'\'' '\''Inst curl [1.0] (1.1 Ubuntu:stable [amd64])'\''' \
        >"${fake_bin}/apt-get"
    chmod 0700 "${fake_bin}/dpkg-query" "${fake_bin}/systemctl" "${fake_bin}/apt-get"
    : >"${source_root}/var/run/reboot-required"
}

teardown() {
    rm -rf -- "${test_root}"
}

@test "software collector writes reduced read-only inventory without refreshing APT" {
    tools_before="$(find "${fake_bin}" -type f -exec sha256sum {} + | sort)"

    run env PATH="${fake_bin}:/usr/bin:/bin" /bin/bash \
        "${project_root}/src/fleet_audit/collectors/software.sh" \
        "${workspace}" "${source_root}"

    [ "${status}" -eq 0 ]
    [ "${output}" = "" ]
    [ "$(find "${workspace}" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)" = \
        $'packages.tsv\npending-updates.txt\nreboot-required.txt\nservices.txt' ]
    [ "$(find "${fake_bin}" -type f -exec sha256sum {} + | sort)" = "${tools_before}" ]
    [ "$(<"${workspace}/packages.tsv")" = \
        $'zlib1g\t1:1.2.13.dfsg-1\tamd64\nacl\t2.3.1-3\tamd64' ]
    [ "$(<"${workspace}/services.txt")" = $'ssh.service\ncron.service' ]
    [ "$(<"${workspace}/pending-updates.txt")" = "2" ]
    [ "$(<"${workspace}/reboot-required.txt")" = "true" ]
}

@test "software collector records a false reboot state when the sentinel is absent" {
    rm -- "${source_root}/var/run/reboot-required"

    run env PATH="${fake_bin}:/usr/bin:/bin" /bin/bash \
        "${project_root}/src/fleet_audit/collectors/software.sh" \
        "${workspace}" "${source_root}"

    [ "${status}" -eq 0 ]
    [ "$(<"${workspace}/reboot-required.txt")" = "false" ]
}

@test "software collector preserves available sources when commands fail" {
    printf '%s\n' '#!/usr/bin/env bash' 'exit 127' >"${fake_bin}/dpkg-query"
    printf '%s\n' '#!/usr/bin/env bash' 'exit 127' >"${fake_bin}/systemctl"
    printf '%s\n' '#!/usr/bin/env bash' 'exit 127' >"${fake_bin}/apt-get"
    chmod 0700 "${fake_bin}/dpkg-query" "${fake_bin}/systemctl" "${fake_bin}/apt-get"

    run env PATH="${fake_bin}:/usr/bin:/bin" /bin/bash \
        "${project_root}/src/fleet_audit/collectors/software.sh" \
        "${workspace}" "${source_root}"

    [ "${status}" -eq 0 ]
    [ "$(find "${workspace}" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)" = \
        $'packages.error\npending-updates.error\nreboot-required.txt\nservices.error' ]
}

@test "software collector rejects empty package output but permits no enabled services" {
    printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"${fake_bin}/dpkg-query"
    printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"${fake_bin}/systemctl"
    chmod 0700 "${fake_bin}/dpkg-query" "${fake_bin}/systemctl"

    run env PATH="${fake_bin}:/usr/bin:/bin" /bin/bash \
        "${project_root}/src/fleet_audit/collectors/software.sh" \
        "${workspace}" "${source_root}"

    [ "${status}" -eq 0 ]
    [ -f "${workspace}/packages.error" ]
    [ -f "${workspace}/services.txt" ]
    [ ! -s "${workspace}/services.txt" ]
}

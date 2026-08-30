#!/usr/bin/env bats

setup() {
    project_root="$(cd -- "${BATS_TEST_DIRNAME}/../.." && pwd -P)"
    test_root="$(mktemp -d)"
    fake_bin="${test_root}/bin"
    workspace="${test_root}/workspace"
    mkdir -- "${fake_bin}" "${workspace}"

    printf '%s\n' '#!/usr/bin/env bash' \
        '[[ "$*" == "-brief link show" ]] || exit 2' \
        'printf '\''%s\n'\'' '\''lo UNKNOWN 00:00:00:00:00:00 <LOOPBACK,UP>'\''' \
        'printf '\''%s\n'\'' '\''eth0@if3 UP 02:00:00:00:00:01 <BROADCAST,UP>'\''' \
        'printf '\''%s\n'\'' '\''wlan0 DOWN 02:00:00:00:00:02 <BROADCAST>'\''' \
        >"${fake_bin}/ip"
    printf '%s\n' '#!/usr/bin/env bash' \
        '[[ "$*" == "-H -l -n -t -u" ]] || exit 2' \
        'printf '\''%s\n'\'' '\''tcp LISTEN 0 128 127.0.0.1:631 0.0.0.0:*'\''' \
        'printf '\''%s\n'\'' '\''tcp LISTEN 0 128 [::1]:631 [::]:*'\''' \
        'printf '\''%s\n'\'' '\''tcp LISTEN 0 128 0.0.0.0:443 0.0.0.0:*'\''' \
        'printf '\''%s\n'\'' '\''udp UNCONN 0 0 [::]:5353 [::]:*'\''' \
        'printf '\''%s\n'\'' '\''tcp LISTEN 0 128 192.0.2.10:8080 0.0.0.0:* users:(("private",pid=1,fd=3))'\''' \
        'printf '\''%s\n'\'' '\''tcp LISTEN 0 128 [2001:db8::10]:9090 [::]:*'\''' \
        >"${fake_bin}/ss"
    chmod 0700 "${fake_bin}/ip" "${fake_bin}/ss"
}

teardown() {
    rm -rf -- "${test_root}"
}

@test "network collector writes only reduced interface and socket facts" {
    tools_before="$(find "${fake_bin}" -type f -exec sha256sum {} + | sort)"

    run env PATH="${fake_bin}:/usr/bin:/bin" /bin/bash \
        "${project_root}/src/fleet_audit/collectors/network.sh" "${workspace}"

    [ "${status}" -eq 0 ]
    [ "${output}" = "" ]
    [ "$(find "${workspace}" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)" = \
        $'interfaces.tsv\nsockets.tsv' ]
    [ "$(find "${fake_bin}" -type f -exec sha256sum {} + | sort)" = "${tools_before}" ]
    [ "$(<"${workspace}/interfaces.tsv")" = $'lo\tunknown\neth0@if3\tup\nwlan0\tdown' ]
    [ "$(<"${workspace}/sockets.tsv")" = \
        $'tcp\t631\tloopback\ntcp\t631\tloopback\ntcp\t443\twildcard\nudp\t5353\twildcard\ntcp\t8080\texternal\ntcp\t9090\texternal' ]
    ! grep -Eqi '00:00|02:00|127\\.|192\\.0\\.2|2001:db8|pid=|private' \
        "${workspace}/interfaces.tsv" "${workspace}/sockets.tsv"
}

@test "network collector preserves sockets when ip is unavailable" {
    printf '%s\n' '#!/usr/bin/env bash' 'exit 127' >"${fake_bin}/ip"
    chmod 0700 "${fake_bin}/ip"

    run env PATH="${fake_bin}:/usr/bin:/bin" /bin/bash \
        "${project_root}/src/fleet_audit/collectors/network.sh" "${workspace}"

    [ "${status}" -eq 0 ]
    [ "$(find "${workspace}" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)" = \
        $'interfaces.error\nsockets.tsv' ]
}

@test "network collector preserves interfaces when ss is unavailable" {
    printf '%s\n' '#!/usr/bin/env bash' 'exit 127' >"${fake_bin}/ss"
    chmod 0700 "${fake_bin}/ss"

    run env PATH="${fake_bin}:/usr/bin:/bin" /bin/bash \
        "${project_root}/src/fleet_audit/collectors/network.sh" "${workspace}"

    [ "${status}" -eq 0 ]
    [ "$(find "${workspace}" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)" = \
        $'interfaces.tsv\nsockets.error' ]
}

@test "network collector reports unavailable when ip and ss both fail" {
    printf '%s\n' '#!/usr/bin/env bash' 'exit 127' >"${fake_bin}/ip"
    printf '%s\n' '#!/usr/bin/env bash' 'exit 127' >"${fake_bin}/ss"
    chmod 0700 "${fake_bin}/ip" "${fake_bin}/ss"

    run env PATH="${fake_bin}:/usr/bin:/bin" /bin/bash \
        "${project_root}/src/fleet_audit/collectors/network.sh" "${workspace}"

    [ "${status}" -eq 10 ]
    [ "$(find "${workspace}" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)" = \
        $'interfaces.error\nsockets.error' ]
}

#!/usr/bin/env bash
# Scans every zoo case and compares the engines that reported a threat with the case's `expect` file
# ("clean", or the one engine that must fire). Exits non-zero on any miss or false alarm.
#   run.sh <booto> <zoo dir>
set -uo pipefail
BOOTO="$1"
ZOO="$2"

planted=0 caught=0 clean=0 alarms=0 bad=0
printf '%-22s | %-13s | %-24s | %s\n' Case Expected Flagged Result
printf -- '-----------------------+---------------+--------------------------+-------\n'
for dir in "${ZOO}"/*/; do
    name="$(basename "${dir}")"
    expect="$(cat "${dir}expect")"
    out="$("${BOOTO}" -c -t "${dir}disk.img" -s "${dir}root" 2>/dev/null)"
    rc=$?
    # Module table rows: "name | status | threats | note"; keep the names whose threat count is above zero.
    flagged="$(printf '%s\n' "${out}" | awk -F' *[|] *' 'NF >= 4 && $3 + 0 > 0 { printf "%s%s", sep, $1; sep = ", " }')"
    if [ "${expect}" = clean ]; then
        clean=$((clean + 1))
        want_rc=0
        want=""
        [ -n "${flagged}" ] && alarms=$((alarms + 1))
    else
        planted=$((planted + 1))
        want_rc=1
        want="${expect}"
        case ", ${flagged}, " in *", ${expect}, "*) caught=$((caught + 1)) ;; esac
    fi
    # Exact match: the expected engine fires and no other engine does.
    if [ "${flagged}" = "${want}" ] && [ "${rc}" -eq "${want_rc}" ]; then
        result=ok
    else
        result="FAIL (exit ${rc})"
        bad=$((bad + 1))
    fi
    printf '%-22s | %-13s | %-24s | %s\n' "${name}" "${expect}" "${flagged:--}" "${result}"
done

echo
echo "Catch rate:       ${caught}/${planted} planted cases"
echo "False-alarm rate: ${alarms}/${clean} clean cases"
[ "${bad}" -eq 0 ] && [ "${planted}" -gt 0 ] && [ "${clean}" -gt 0 ]

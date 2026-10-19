#!/usr/bin/env bash
# Local convenience wrapper: runs every integration verification script and
# prints each one's final result line. Not part of CI - the CI `integration`
# job runs the scripts individually so a failure is attributed to one script.
set -uo pipefail
cd "$(dirname "$0")/.."

FAILED=0
for script in verify_ingest verify_recovery verify_incidents verify_correlation verify_benchmarks; do
    echo
    echo "############################################################"
    echo "# $script"
    echo "############################################################"
    if bash "scripts/$script.sh" 2>&1 | tail -6; then
        :
    else
        FAILED=1
    fi
done

echo
if [ "$FAILED" -eq 0 ]; then
    echo "ALL VERIFICATION SCRIPTS COMPLETED"
else
    echo "ONE OR MORE VERIFICATION SCRIPTS FAILED"
    exit 1
fi

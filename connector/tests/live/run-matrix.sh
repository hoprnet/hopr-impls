#!/usr/bin/env bash
# Runs run-cell.sh for every Blokli build and scenario, one cell at a time.
#
# Environment: the variables of run-cell.sh, plus
#   BUILDS      Blokli builds (default "0.14.5 main")
#   SCENARIOS   scenarios (default "anvil-redemption geth-redemption")
set -u
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
failed=0
for scenario in ${SCENARIOS:-anvil-redemption geth-redemption}; do
  for build in ${BUILDS:-0.14.5 main}; do
    started=$(date +%s)
    echo "$(date '+%H:%M:%S') start ${scenario} ${build}"
    "${here}/run-cell.sh" "${build}" "${scenario}" || failed=1
    echo "$(date '+%H:%M:%S') end ${scenario} ${build} after $(($(date +%s) - started)) s"
  done
done
exit "${failed}"

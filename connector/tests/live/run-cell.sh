#!/usr/bin/env bash
# Runs one cell of the live test matrix: one Blokli build against one scenario.
# Starts the chain, waits for Blokli, runs the redemption_retry_loop test, writes the output and tears everything down.
#
# usage: run-cell.sh <blokli: 0.14.5|main> <scenario: anvil-redemption|geth-redemption>
#
# Required environment:
#   BLOKLI_BUILDS_DIR  directory holding bloklid-<blokli>/bin/{bloklid,blokli-contract-deployer}
#   ANVIL_BIN          path to anvil (scenario anvil-redemption)
#   GETH_BIN           path to geth (scenario geth-redemption)
# Optional:
#   OUT_DIR            output directory (default ./live-results)
#   GETH_EXTRA_ARGS    extra geth flags (scenario geth-redemption)
#   any variable read by the test (REDEMPTION_*, see README.md) and by the chain scripts (UNMINED_TIMEOUT, GENESIS_BASE_FEE)
# Output: $OUT_DIR/<scenario>-<blokli>.txt, the same without colour codes in .clean, and the chain logs in
# $OUT_DIR/chain-<scenario>-<blokli>.log.
set -u

if [ $# -ne 2 ]; then
  echo "usage: run-cell.sh <blokli: 0.14.5|main> <scenario: anvil-redemption|geth-redemption>" >&2
  exit 2
fi
build=$1
scenario=$2

die() {
  echo "run-cell.sh: $*" >&2
  exit 1
}

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "${here}/../../.." && pwd)

: "${BLOKLI_BUILDS_DIR:?set BLOKLI_BUILDS_DIR to the directory holding bloklid-<build>/bin/{bloklid,blokli-contract-deployer}}"
builds_dir=$(cd "${BLOKLI_BUILDS_DIR}" 2>/dev/null && pwd) || die "BLOKLI_BUILDS_DIR=${BLOKLI_BUILDS_DIR} is not a directory"
bloklid="${builds_dir}/bloklid-${build}/bin/bloklid"
deployer="${builds_dir}/bloklid-${build}/bin/blokli-contract-deployer"
[ -x "${bloklid}" ] || die "${bloklid} not found, build it as described in README.md"
[ -x "${deployer}" ] || die "${deployer} not found, build it as described in README.md"

case "${scenario}" in
anvil-redemption)
  : "${ANVIL_BIN:?set ANVIL_BIN to the anvil binary}"
  [ -x "${ANVIL_BIN}" ] || die "ANVIL_BIN=${ANVIL_BIN} is not executable"
  blokli_port=18080 rpc_port=18545
  chain_script=chain.sh
  chain_env=(ANVIL_BIN="${ANVIL_BIN}" ANVIL_PORT="${rpc_port}")
  rpc_pattern="${ANVIL_BIN} .*--port ${rpc_port}"
  test_path="sequencer_live_tests::redemption_retry_loop"
  rpc_var=ANVIL_URL
  ;;
geth-redemption)
  : "${GETH_BIN:?set GETH_BIN to the geth binary}"
  [ -x "${GETH_BIN}" ] || die "GETH_BIN=${GETH_BIN} is not executable"
  blokli_port=28080 rpc_port=28545
  chain_script=chain-geth.sh
  chain_env=(GETH_BIN="${GETH_BIN}" GETH_PORT="${rpc_port}" GETH_EXTRA_ARGS="${GETH_EXTRA_ARGS:-}")
  rpc_pattern="${GETH_BIN} .*--http.port ${rpc_port}"
  test_path="sequencer_live_geth_tests::redemption_retry_loop"
  rpc_var=GETH_URL
  ;;
*) die "unknown scenario ${scenario}, expected anvil-redemption or geth-redemption" ;;
esac

if command -v cargo >/dev/null 2>&1; then
  cargo_cmd=(cargo)
else
  cargo_cmd=(nix develop -c cargo)
fi

out_dir="${OUT_DIR:-./live-results}"
mkdir -p "${out_dir}" || die "cannot create ${out_dir}"
out_dir=$(cd "${out_dir}" && pwd)
out="${out_dir}/${scenario}-${build}.txt"
chain_log="${out_dir}/chain-${scenario}-${build}.log"
data_dir=$(mktemp -d "${TMPDIR:-/tmp}/live-${scenario}-${build}.XXXXXX") || die "cannot create a data directory"
chain_pid=""

cleanup() {
  if [ -n "${chain_pid}" ]; then
    kill "${chain_pid}" 2>/dev/null
    wait "${chain_pid}" 2>/dev/null
  fi
  pkill -f "${bloklid} " 2>/dev/null
  pkill -f "${bloklid}\$" 2>/dev/null
  pkill -f "${rpc_pattern}" 2>/dev/null
  sleep 1
  rm -rf "${data_dir}"
  [ -f "${out}" ] && sed 's/\x1b\[[0-9;]*m//g' "${out}" >"${out}.clean"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

start=$(date +%s)
env BLOKLID_BIN="${bloklid}" DEPLOYER_BIN="${deployer}" DATA_DIR="${data_dir}" BLOKLI_PORT="${blokli_port}" \
  "${chain_env[@]}" "${here}/${chain_script}" >"${chain_log}" 2>&1 &
chain_pid=$!

ready=0
for _ in $(seq 1 120); do
  if curl -sf -X POST "http://127.0.0.1:${blokli_port}/graphql" -H 'content-type: application/json' \
    --data '{"query":"{chainInfo{... on ChainInfo{chainId}}}"}' | grep -q chainId; then
    ready=1
    break
  fi
  kill -0 "${chain_pid}" 2>/dev/null || break
  sleep 2
done
[ "${ready}" = 1 ] || die "Blokli did not answer on port ${blokli_port} for ${scenario} ${build}, see ${chain_log}"

cd "${repo}" || die "cannot enter ${repo}"
env BLOKLI_URL="http://127.0.0.1:${blokli_port}" "${rpc_var}=http://127.0.0.1:${rpc_port}" BLOKLI_LABEL="${build}" \
  RUST_LOG="${RUST_LOG:-hopr_chain_connector=debug}" \
  "${cargo_cmd[@]}" test -p hopr-chain-connector --all-features --lib "${test_path}" -- \
  --ignored --nocapture --test-threads=1 >"${out}" 2>&1
status=$?
echo "test exit: ${status} ; seconds: $(($(date +%s) - start))" | tee -a "${out}"
exit "${status}"

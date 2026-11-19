#!/usr/bin/env bash
# Prints the result lines of every cell in an output directory of run-cell.sh.
# usage: summarize.sh <out dir>
set -u
if [ $# -ne 1 ] || [ ! -d "$1" ]; then
  echo "usage: summarize.sh <out dir>" >&2
  exit 2
fi
shopt -s nullglob
for file in "$1"/*.txt; do
  echo "== $(basename "${file}" .txt)"
  sed 's/\x1b\[[0-9;]*m//g' "${file}" |
    grep -E "start base fee|channels start|peak reached|relief starts|peak gap:|base fee at start|diagnosis reasons|gap closed|never closed|\] errors|test exit" |
    sed -E 's/^\[[^]]*\] //' | cut -c1-260
done

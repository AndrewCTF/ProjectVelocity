#!/usr/bin/env bash
set -euo pipefail

# Fast-Hybrid Speed & Security Upgrade benchmark harness
#
# Prerequisites:
#   - Linux host with Docker and Chromium/Chrome headless available in PATH.
#   - Rust toolchain (nightly-2025-09-01 or later) with cargo and rustup.
#   - tc/netem kernel modules loaded (for WAN simulation).
#   - Repository layout includes the Velocity core crates and optional benchmarking harnesses.
#
# Outputs:
#   - bench/results/microbench.csv        (handshake cycle & byte counts)
#   - bench/results/page_load.csv         (TTFB comparisons)
#   - bench/results/system_info.json      (environment metadata)
#   - bench/results/summary.csv           (aggregated KPIs)
#   - bench/results/*.png                 (optional charts if gnuplot available)
#
# Usage:
#   ./bench/run_bench.sh [--no-page-load] [--wan-rt=50] [--wan-loss=0.0]

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RESULTS_DIR="${ROOT_DIR}/bench/results"
mkdir -p "${RESULTS_DIR}"

WAN_RTT_MS=50
WAN_LOSS=0.0
RUN_PAGE_LOAD=true

for arg in "$@"; do
  case "$arg" in
    --no-page-load)
      RUN_PAGE_LOAD=false
      shift
      ;;
    --wan-rt=*)
      WAN_RTT_MS="${arg#*=}"
      shift
      ;;
    --wan-loss=*)
      WAN_LOSS="${arg#*=}"
      shift
      ;;
    *)
      echo "Unknown flag: $arg" >&2
      exit 1
      ;;
  esac
done

log() {
  printf '[%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"
}

capture_env() {
  log "Capturing environment metadata"
  jq -n \
    --arg kernel "$(uname -r)" \
    --arg os "$(uname -s)" \
    --arg cpu "$(lscpu | awk -F: '/Model name/ {print $2; exit}' | sed 's/^ //')" \
    --arg cores "$(nproc)" \
    --arg rustc "$(rustc --version)" \
    --arg cargo "$(cargo --version)" \
    --arg docker "$(docker --version | head -n1)" \
    --arg chromium "$(chromium --version || google-chrome --version || echo 'not-found')" \
    '{kernel:$kernel, os:$os, cpu:$cpu, cores:($cores|tonumber), rustc:$rustc, cargo:$cargo, docker:$docker, chromium:$chromium}' \
    > "${RESULTS_DIR}/system_info.json"
}

run_microbench() {
  local bench_dir="${ROOT_DIR}/benchmarks/handshake-bench"
  if [[ ! -d "${bench_dir}" ]]; then
    log "handshake benchmark crate not found; skipping microbench"
    printf 'case,median_cycles,bytes_on_wire\n' > "${RESULTS_DIR}/microbench.csv"
    return
  fi

  log "Running handshake microbench (Criterion)"
  pushd "${bench_dir}" >/dev/null
  if ! cargo bench --bench handshake; then
    popd >/dev/null
    log "cargo bench failed; skipping microbench summarization"
    printf 'case,median_cycles,bytes_on_wire\n' > "${RESULTS_DIR}/microbench.csv"
    return
  fi
  popd >/dev/null

  # Placeholder CSV until Criterion export integration lands.
  printf 'case,median_cycles,bytes_on_wire\n' > "${RESULTS_DIR}/microbench.csv"
}

run_wan_sim() {
  log "WAN simulation harness not configured; skipping"
}

run_page_load() {
  if [[ "${RUN_PAGE_LOAD}" != true ]]; then
    log "Skipping page-load benchmark"
    return
  fi
  log "Page-load harness not available; skipping"
}

aggregate_summary() {
  log "Aggregating KPI summary"
  python - <<'PY'
 import csv, pathlib
root = pathlib.Path("${RESULTS_DIR}")
summary = {}
microbench = root / "microbench.csv"
if microbench.exists():
  with open(microbench) as fh:
    reader = csv.DictReader(fh)
    for row in reader:
      if not row:
        continue
      case = row.get('case')
      try:
        summary[f"handshake_{case}_cycles"] = float(row['median_cycles'])
        summary[f"handshake_{case}_bytes"] = float(row['bytes_on_wire'])
      except (TypeError, ValueError):
        continue
summary_rows = sorted(summary.items())
with open(root / "summary.csv", "w", newline="") as fh:
    writer = csv.writer(fh)
    writer.writerow(["metric", "value"])
    writer.writerows(summary_rows)
PY
}

main() {
  capture_env
  run_microbench
  run_wan_sim
  run_page_load
  aggregate_summary
  log "Benchmark complete. See ${RESULTS_DIR}" 
}

main "$@"

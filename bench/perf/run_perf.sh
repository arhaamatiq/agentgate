#!/usr/bin/env bash
# Latency/throughput of the deterministic rule path through the full stack.
#
# The load generator runs as a container on the compose network and calls
# gateway:8080/v1/check with the real dev-set tool calls the rule path
# decides (escalating calls are excluded by a probe pass). Every request
# goes through the complete pipeline: rules, Redis trajectory write, Kafka
# audit produce. Results land in bench/results/perf/.
#
#   docker compose up -d --build && bench/perf/run_perf.sh
#
# RATES (default "1000 2000 5000") picks the open-loop rates; CLOSED=0 skips
# the closed-loop max-throughput run.
set -euo pipefail
cd "$(dirname "$0")/../.."
DUR=${DUR:-30s}
RATES=${RATES:-1000 2000 5000}
out=bench/results/perf
mkdir -p "$out"

loadgen() {
  docker compose run --rm --no-deps -v "$PWD/bench:/bench" --entrypoint /usr/local/bin/agentgate-loadgen gateway \
    -url http://gateway:8080/v1/check -dataset /bench/data/dev_set.jsonl -duration "$DUR" "$@"
}

for rate in $RATES; do
  echo "== open loop ${rate} req/s (audit: ${AGENTGATE_AUDIT_MODE:-async})"
  loadgen -mode open -rate "$rate" -concurrency 64 -out "/bench/results/perf/open_${rate}rps_${AGENTGATE_AUDIT_MODE:-async}.json" | tail -n +1 >/dev/null
  python3 -c "import json,sys;d=json.load(open('$out/open_${rate}rps_${AGENTGATE_AUDIT_MODE:-async}.json'));print(f\"  achieved {d['achieved_rps']:.0f} req/s  p50 {d['latency_ms']['p50']:.2f} ms  p99 {d['latency_ms']['p99']:.2f} ms  p99.9 {d['latency_ms']['p99.9']:.2f} ms  errors {d['errors']}\")"
done
[[ ${CLOSED:-1} == 0 ]] && exit 0
echo "== closed loop, 64 workers (max throughput)"
loadgen -mode closed -concurrency 64 -out "/bench/results/perf/closed_64w_${AGENTGATE_AUDIT_MODE:-async}.json" >/dev/null
python3 -c "import json;d=json.load(open('$out/closed_64w_${AGENTGATE_AUDIT_MODE:-async}.json'));print(f\"  {d['achieved_rps']:.0f} req/s  p50 {d['latency_ms']['p50']:.2f} ms  p99 {d['latency_ms']['p99']:.2f} ms  errors {d['errors']}\")"

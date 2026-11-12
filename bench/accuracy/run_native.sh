#!/usr/bin/env bash
# Score a benchmark set through a natively built gateway and judge (no Docker,
# Redis or Kafka: in-memory state, audit off). The Docker and native paths
# make identical decisions on the dev set.
#
#   bench/accuracy/run_native.sh <set> <label> <mode> <cassette> [base-cassette]
#
#   set       dev
#   mode      record | replay | extend  (see agentgate/judge_service/server.py)
#   cassette  judge responses file under bench/cassettes/
#   base      copied to <cassette> first, so an extend run starts from an
#             earlier run's responses and calls the model only for prompts the
#             rule change created
#
# record/extend need OPENAI_API_KEY; replay needs none.
set -euo pipefail
cd "$(dirname "$0")/../.."
[[ $# -ge 4 ]] || { sed -n '2,16p' "$0"; exit 2; }
set_name=$1 label=$2 mode=$3 cassette=$4 base=${5:-}
PY=${PYTHON:-.venv/bin/python}
port=${PORT:-18090} judge_port=${JUDGE_PORT:-50071}

work=$(mktemp -d)
(cd gateway && go build -o "$work/agentgate-gateway" ./cmd/agentgate-gateway)
if [[ -n $base ]]; then cp "$base" "$cassette"; fi

AGENTGATE_JUDGE_PORT=$judge_port AGENTGATE_JUDGE_CASSETTE=$cassette AGENTGATE_JUDGE_CASSETTE_MODE=$mode \
  "$PY" -m agentgate.judge_service.server 2>"$work/judge.log" &
judge=$!
AGENTGATE_LISTEN=127.0.0.1:$port AGENTGATE_JUDGE_ADDRESS=127.0.0.1:$judge_port \
  "$work/agentgate-gateway" serve --config deploy/policy.yaml 2>"$work/gateway.log" &
gw=$!
trap 'kill $judge $gw 2>/dev/null; wait 2>/dev/null; rm -rf "$work"' EXIT
# The gateway turns ready without the judge, so also wait for the judge's
# port. curl's HTTP/2 request to a gRPC server ends in a stream error (92);
# only 7 means nothing ever listened.
rc=0
curl -s -o /dev/null --http2-prior-knowledge --retry 40 --retry-connrefused --retry-delay 1 \
  "http://127.0.0.1:$judge_port/" || rc=$?
[[ $rc != 7 ]] || { cat "$work/judge.log" >&2; exit 1; }
curl -sf --retry 40 --retry-connrefused --retry-delay 1 "http://127.0.0.1:$port/readyz" >/dev/null

desc="$mode gpt-4o-mini, $cassette"
[[ -n $base ]] && desc+=" (extended from $base)"
"$PY" bench/accuracy/run_accuracy.py --set "$set_name" --gateways "http://127.0.0.1:$port" \
  --label "$label" --judge-mode "$desc; native gateway"

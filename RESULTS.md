# AgentGate results

Every number below is read from a result file written by a committed script
(`bench/make_results.py` renders this page). Rerun everything with
`make bench`; see [bench/README.md](bench/README.md) for each script.

## Headline numbers

| Claim | Measured | Source |
|---|---|---|
| Decision latency at 1,000 req/s, inside the gateway (p99) | **0.58 ms** | [`bench/results/perf/open_1000rps_async.json`](bench/results/perf/open_1000rps_async.json) |
| Decision latency at 5,000 req/s, inside the gateway (p99) | **1.90 ms** | [`bench/results/perf/open_5000rps_async.json`](bench/results/perf/open_5000rps_async.json) |
| Latency at 1,000 req/s, end to end through the full stack (p99) | **7.93 ms** (p50 1.10 ms) | [`bench/results/perf/open_1000rps_async.json`](bench/results/perf/open_1000rps_async.json) |
| Max throughput, one gateway replica (closed loop, 64 clients) | **17,258 req/s** (p99 18.00 ms, 0 errors) | [`bench/results/perf/closed_64w_async.json`](bench/results/perf/closed_64w_async.json) |
| Decisions streamed gateway → Kafka → Postgres | **25,000**, 0 lost, 0 duplicated, with 2 injected faults | [`bench/results/stream/stream_25000.json`](bench/results/stream/stream_25000.json) |
| Tamper detection (edited, deleted, truncated, rewritten, forged rows) | **6/6 attacks detected**; untampered copy verifies clean | [`bench/results/tamper/tamper.json`](bench/results/tamper/tamper.json) |
| Fail-closed under component failure | **8/8 scenarios blocked**, 0 calls reached the tool server | [`bench/results/failclosed/failclosed.json`](bench/results/failclosed/failclosed.json) |
| Dev benchmark through the gateway (all 466 decisions) | **recall 99.7%, precision 97.2%** | [`bench/results/accuracy/dev_live_r1.json`](bench/results/accuracy/dev_live_r1.json) |
| Run 007 as published (Python, 393 of 466 decisions scored) | recall 99.6%, precision 98.1% | [`bench/results/accuracy/dev_live_r1.json`](bench/results/accuracy/dev_live_r1.json) (re-derived) |
| Go engine vs Python reference | 48,550/48,716 identical; 0 where Go is more permissive | [`bench/results/parity.json`](bench/results/parity.json) |

## Accuracy

The 99.6% / 98.1% figures from run 007 are **development-set** numbers: the
rules were iterated against this same suite from run 001 (67.3% recall) to run
007. The full history, read from the committed reports, is in
[bench/results/HISTORY.md](bench/results/HISTORY.md).

### Development set through the gateway path

The frozen dev set replays run 007's exact tool calls (466 decisions: 340
single-turn runs and 30 multi-turn trajectories) through `/v1/check` on two
gateway replicas, with trajectory steps alternating between replicas so the
judge only sees full history if Redis-shared state works.

| Run | Decisions | Recall | Precision | FP rate | TP | FN | FP | TN |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Gateway, live judge, run 1 | 466 | 99.7% | 97.2% | 6.0% | 315 | 1 | 9 | 141 |
| Gateway, live judge, run 2 | 466 | 99.7% | 97.2% | 6.0% | 315 | 1 | 9 | 141 |
| Gateway, live judge, run 3 | 466 | 99.7% | 97.2% | 6.0% | 315 | 1 | 9 | 141 |
| Gateway, judge replayed from cassette (no API key) | 466 | 99.7% | 97.2% | 6.0% | 315 | 1 | 9 | 141 |
| Gateway, run 007's agent names (label leak reproduced) | 466 | 99.7% | 97.2% | 6.0% | 315 | 1 | 9 | 141 |
| Python in-process engine, judge replayed | 466 | 99.7% | 97.2% | 6.0% | 315 | 1 | 9 | 141 |
| Python in-process engine, live judge today | 466 | 99.7% | 96.9% | 6.7% | 315 | 1 | 10 | 140 |
| Gateway, current rules (judge: run 1's cassette, extended) | 466 | 99.7% | 97.2% | 6.0% | 315 | 1 | 9 | 141 |
| Run 007 as published (Python) | 393 | 99.6% | 98.1% | 3.6% | 253 | 1 | 5 | 134 |
| Gateway on the same 393 decisions run 007 scored | 393 | 99.6% | 97.3% | 5.0% | 253 | 1 | 7 | 132 |

What this shows:

- **Recall did not regress** (99.7% vs 99.6%). **Precision did: 97.2% vs 98.1%.**
  The target was no regression on both; precision misses it by 0.9 points.
- **The gateway is not the cause.** Fed the gateway's recorded judge responses,
  the in-process Python engine built 186 judge prompts, all byte-identical to
  the gateway's (0 misses), and made 0 different decisions.
  Run live today, the Python engine scores 96.9% precision. Every disagreement
  with run 007 is a Tier 2 (LLM judge) decision; the rule path agrees on all of
  them. The same judge model (gpt-4o-mini-2024-07-18) now answers a few
  borderline prompts differently than it did in run 007.
- **Run 007 never scored 73 of its 466 decisions.** A crash in the Tier 2
  prompt builder (`ScopePolicy._OPERATION_SUBSUMPTION` accessed as a pydantic
  private attribute) turned them into errors that recall/precision skipped.
  Fixed; every run above scores all 466.
- **The label leak did not matter.** Run 007 named agents after the scenario
  (`test-data_block_15`), and that name reached the judge prompt. Reproducing
  it gives the same numbers as opaque IDs.
- Three live runs gave identical results; the cassette replay reproduces them
  exactly without an API key.

## Latency and throughput

Load generator: [`gateway/cmd/agentgate-loadgen`](gateway/cmd/agentgate-loadgen/main.go), run as a
container on the compose network against one gateway replica. Payloads are
the dev-set tool calls the rule path decides on its own. Every request runs
the full pipeline: rules, a Redis trajectory write, and a Kafka audit produce.
Open-loop runs measure from each request's scheduled send time, so queueing
shows up as latency (no coordinated omission). "Inside the gateway" is the
decision time the gateway reports per request.

| Load | Achieved | p50 | p90 | p99 | p99.9 | p99 inside gateway | Errors | Source |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| 1,000 req/s | 1000/s | 1.10 ms | 2.27 ms | 7.93 ms | 70.78 ms | 0.58 ms | 0 | [`bench/results/perf/open_1000rps_async.json`](bench/results/perf/open_1000rps_async.json) |
| 2,000 req/s | 2000/s | 1.18 ms | 3.45 ms | 25.50 ms | 62.41 ms | 0.98 ms | 0 | [`bench/results/perf/open_2000rps_async.json`](bench/results/perf/open_2000rps_async.json) |
| 5,000 req/s | 5000/s | 0.99 ms | 13.74 ms | 307.57 ms | 399.46 ms | 1.90 ms | 0 | [`bench/results/perf/open_5000rps_async.json`](bench/results/perf/open_5000rps_async.json) |
| 1,000 req/s, sync audit | 1000/s | 1.49 ms | 4.78 ms | 27.43 ms | 113.29 ms | 0.78 ms | 0 | [`bench/results/perf/open_1000rps_sync.json`](bench/results/perf/open_1000rps_sync.json) |
| closed loop, 64 clients | 17258/s | 2.69 ms | 7.40 ms | 18.00 ms | 37.19 ms | 2.59 ms | 0 | [`bench/results/perf/closed_64w_async.json`](bench/results/perf/closed_64w_async.json) |

Rule engine alone (`go test -bench`, dev-set calls, one core):

```
cpu: Apple M1 Pro
BenchmarkEvaluateDevSet-8   	  199278	     26858 ns/op	    1505 B/op	      24 allocs/op
```

## Audit pipeline

[`bench/stream/run_stream.py`](bench/stream/run_stream.py) sent **25,000 decisions** across both gateway replicas while injecting the faults below. It drives the gateways from the host through Docker Desktop's port forwarding (25/s); throughput is measured inside the compose network above.

- auditor SIGKILL + restart
- kafka broker restart

Result: **0 missing, 0 duplicated**; verifier INTACT over 25,466 rows, 25,466 matched byte-for-byte to their Kafka records, 147 signed checkpoints verified.

[`bench/stream/tamper.py`](bench/stream/tamper.py): append-only enforcement, then attacks by a
database superuser (triggers disabled) on a copy of the log:

| Check | Result |
|---|---|
| `writer_update` | rejected |
| `owner_update` | rejected |
| `owner_delete` | rejected |
| `owner_truncate` | rejected |
| control copy, no attack | clean |
| `edit_event` | **detected**: hash_mismatch, kafka_source_mismatch |
| `edit_column` | **detected**: column_mismatch |
| `delete_middle` | **detected**: broken_link, missing_rows |
| `truncate_tail` | **detected**: checkpoint_row_missing |
| `rewrite_chain` | **detected**: checkpoint_mismatch, kafka_source_mismatch |
| `forge_append` | **detected**: no_kafka_source |

## Fail-closed

| Scenario | Result | Detail |
|---|---|---|
| control_all_up | pass | allowed; 1 tool execution |
| judge_down | pass | judge_unavailable |
| judge_hung | pass | judge_unavailable |
| judge_llm_error | pass | tier2_error |
| redis_down | pass | state_unavailable, state_unavailable |
| audit_down_sync | pass | audit_unavailable |
| gateway_down | pass | SDK: BLOCKED gateway_unavailable; direct to tool server: UNREACHABLE URLError |
| rule_fault | pass | rule_engine_error, rule_engine_error |

## Go/Python parity

[`bench/parity/run_parity.sh`](bench/parity/run_parity.sh) runs 48,716 inputs through the Python
reference and the Go engine: every benchmark tool call under several scopes, plus
fuzzed SQL, paths, URLs and commands.

- identical decision, policy, severity and reasoning: **48,550**
- Go stricter (data-modifying CTEs the Python engine reads as SELECT): **162**
- same verdict, different explanation (adversarial token soup): **4**
- Go more permissive, or any mismatch on benchmark inputs: **0**

## Environment and caveats

- Apple M1 Pro (8 cores), Docker Desktop 29.4 VM with 8 vCPUs and 8 GB, all
  services and the load generator in the same VM. During the runs, an unrelated
  local Kubernetes cluster (kind, 4 nodes) shared that VM.
- The current-rules dev run used a native build
  ([bench/accuracy/run_native.sh](bench/accuracy/run_native.sh)): one gateway, in-memory state, audit
  off. Its first run makes the same decision as the Docker stack on 466 of 466.
- Kubernetes manifests (`deploy/k8s`) render with `kubectl kustomize`; this run
  did not apply them to a live cluster.
- The dev benchmark's ground-truth labels come from run 007's hybrid evaluator
  (rules plus a gpt-4o-mini reviewer); they are not human-adjudicated.

# AgentGate results

Every number below is read from a result file written by a committed script
(`bench/make_results.py` renders this page). Rerun everything with
`make bench`; see [bench/README.md](bench/README.md) for each script.

## Headline numbers

| Claim | Measured | Source |
|---|---|---|
| Rule-path p99 at 1,000 req/s | **NOT YET MEASURED** | `bench/perf/run_perf.sh` |
| Max throughput | **NOT YET MEASURED** | `bench/perf/run_perf.sh` |
| Decisions streamed with zero loss | **NOT YET MEASURED** | `bench/stream/run_stream.py` |
| Chain verification catches edited/deleted rows | **NOT YET MEASURED** | `bench/stream/tamper.py` |
| Fail-closed under component failure | **NOT YET MEASURED** | `bench/failclosed/run_failclosed.py` |
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

**NOT YET MEASURED** — run `bench/perf/run_perf.sh` with the stack up.

## Audit pipeline

**NOT YET MEASURED** — run `bench/stream/run_stream.py`.

**NOT YET MEASURED** — run `bench/stream/tamper.py`.

## Fail-closed

**NOT YET MEASURED** — run `bench/failclosed/run_failclosed.py`. Unit-level coverage of every fail-closed path
runs in `go test ./...` (`internal/gateway/gateway_test.go`, `internal/rules/engine_test.go`).

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

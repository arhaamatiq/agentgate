# Benchmarks

Every number in [RESULTS.md](../RESULTS.md) comes from a script in this
directory writing to `bench/results/`. `bench/make_results.py` renders
RESULTS.md (and the README results table) from those files; a metric with no
result file is shown as NOT YET MEASURED.

```bash
docker compose up -d --build   # the stack the scripts drive
make bench                     # everything below, then regenerate RESULTS.md
```

## Datasets (`data/`)

| File | What | Provenance |
|---|---|---|
| `dev_set.jsonl` | 370 test runs, 466 labeled decisions | Frozen from run 007 (`agenttest/reports/run_007_raw.json`) by `accuracy/freeze_dev_set.py`: the exact tool calls gpt-4o-mini generated for the 180 adversarial scenarios, with run 007's ground-truth labels. Agent IDs are opaque; the original names leaked the label. |

The dev set is a **development** set: the rules were iterated on it from run
001 to run 007.

## Scripts

| Script | Measures | Output |
|---|---|---|
| `parity/run_parity.sh` | Go rule engine vs the Python reference on ~50k inputs | `results/parity.json` |
| `accuracy/run_accuracy.py` | Recall/precision through the gateway (`/v1/check`), trajectory steps alternating across two replicas | `results/accuracy/<label>.json`, per-decision `.decisions.jsonl` |
| `accuracy/run_native.sh` | The same, through a natively built gateway and judge (no Docker); `extend` mode reuses an earlier run's judge answers so a rule change is measured in isolation | same |
| `accuracy/run_python_reference.py` | The in-process Python engine on the same set; with `--judge replay:` it proves prompt and verdict identity with the gateway | `results/accuracy/python_reference_*.json` |
| `accuracy/history.py` | Run history 001→007 from the committed reports, plus every gateway run | `results/HISTORY.md` |
| `perf/run_perf.sh` | Open-loop latency at 1k/2k/5k req/s and closed-loop max throughput, full stack | `results/perf/*.json` |
| `stream/run_stream.py` | N decisions through Kafka into Postgres with the auditor killed and Kafka restarted mid-run; loss, duplicates, verification | `results/stream/stream_<N>.json` |
| `stream/tamper.py` | Append-only enforcement and six superuser attacks on a copy of the log | `results/tamper/tamper.json` |
| `failclosed/run_failclosed.py` | Seven component failures; each call must be blocked and never reach the tool server | `results/failclosed/failclosed.json` |

## Reproducing accuracy without an API key

The judge service records the model's raw response for every prompt to a
cassette (`cassettes/*.jsonl`) during live runs. Replaying a cassette serves
those responses by prompt digest, so a run on your machine makes the same
decisions as the recorded one; a prompt that is not in the cassette blocks.

```bash
make bench-accuracy          # replay (default)
make bench-accuracy LIVE=1   # call the model (needs OPENAI_API_KEY)
make bench-accuracy-native   # replay without Docker
```

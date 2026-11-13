.PHONY: install dev test test-py test-go lint format proto up down bench bench-accuracy bench-accuracy-native bench-perf bench-stream bench-tamper bench-failclosed parity results clean

PY ?= .venv/bin/python

install:
	uv pip install -e .

dev:
	uv pip install -e ".[dev,all]"

test: test-py test-go

test-py:
	$(PY) -m pytest tests/ -q

test-go:
	cd gateway && go vet ./... && go test ./...

lint:
	uv run ruff check agentgate/ tests/
	cd gateway && test -z "$$(gofmt -l .)"

format:
	uv run ruff format agentgate/ tests/
	cd gateway && gofmt -w .

proto:
	./scripts/gen_proto.sh

# ---- stack -----------------------------------------------------------------

up:
	docker compose up -d --build

down:
	docker compose down -v

# ---- benchmarks (stack must be up; see bench/README.md) --------------------
# The accuracy target replays the recorded judge responses, so it needs no
# API key and reproduces the committed numbers exactly. LIVE=1 calls the model.

bench: parity bench-accuracy bench-perf bench-stream bench-tamper bench-failclosed results

parity:
	./bench/parity/run_parity.sh

bench-accuracy:
ifeq ($(LIVE),1)
	AGENTGATE_JUDGE_CACHE_TTL=0 AGENTGATE_JUDGE_CASSETTE= docker compose up -d gateway gateway-2 judge
	for set in dev; do \
		$(PY) bench/accuracy/run_accuracy.py --set $$set --label $${set}_live_local --judge-mode live || exit 1; \
	done
else
	for run in dev:dev_op_r1; do \
		set=$${run%%:*}; cassette=$${run#*:}; \
		AGENTGATE_JUDGE_CACHE_TTL=0 AGENTGATE_JUDGE_CASSETTE=/cassettes/$$cassette.jsonl AGENTGATE_JUDGE_CASSETTE_MODE=replay \
			OPENAI_API_KEY= docker compose up -d gateway gateway-2 judge && sleep 5 && \
		$(PY) bench/accuracy/run_accuracy.py --set $$set --label $${set}_replay_local --judge-mode "replay of $$cassette" || exit 1; \
	done
endif

# Same replay without Docker: a native gateway and judge per set.
bench-accuracy-native:
	for run in dev:dev_op_r1; do \
		OPENAI_API_KEY= ./bench/accuracy/run_native.sh $${run%%:*} $${run%%:*}_replay_native replay \
			bench/cassettes/$${run#*:}.jsonl || exit 1; \
	done

bench-perf:
	./bench/perf/run_perf.sh
	AGENTGATE_AUDIT_MODE=sync docker compose up -d gateway
	DUR=30s RATES=1000 CLOSED=0 AGENTGATE_AUDIT_MODE=sync ./bench/perf/run_perf.sh
	docker compose up -d gateway
	cd gateway && go test ./internal/rules/ -run XXX -bench EvaluateDevSet -benchtime 5s | grep -E "Benchmark|cpu:" > ../bench/results/perf/engine_bench.txt

bench-stream:
	$(PY) bench/stream/run_stream.py --decisions 25000

bench-tamper:
	$(PY) bench/stream/tamper.py

bench-failclosed:
	$(PY) bench/failclosed/run_failclosed.py

results:
	$(PY) bench/accuracy/history.py > /dev/null
	$(PY) bench/make_results.py > /dev/null
	@echo "RESULTS.md and README results table regenerated"

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -rf dist/ build/ *.egg-info/ gateway/bin/

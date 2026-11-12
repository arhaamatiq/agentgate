#!/usr/bin/env bash
# Regenerate gRPC stubs for the Go gateway and the Python judge.
# Generated code is committed; you only need this after editing the .proto.
# Requires: protoc-gen-go, protoc-gen-go-grpc (go install ...), grpcio-tools.
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-.venv/bin/python}"
export PATH="$(go env GOPATH)/bin:$PATH"

rm -rf gateway/gen/judgev1 && mkdir -p gateway/gen/judgev1
"$PY" -m grpc_tools.protoc -Iproto \
  --go_out=gateway --go_opt=module=github.com/arhaamatiq/agentgate/gateway \
  --go-grpc_out=gateway --go-grpc_opt=module=github.com/arhaamatiq/agentgate/gateway \
  proto/agentgate/judge/v1/judge.proto

out=agentgate/judge_service/gen
rm -rf "$out" && mkdir -p "$out" && touch "$out/__init__.py"
"$PY" -m grpc_tools.protoc -Iproto/agentgate/judge/v1 \
  --python_out="$out" --pyi_out="$out" --grpc_python_out="$out" \
  proto/agentgate/judge/v1/judge.proto
# grpc_tools emits a top-level import; make it package-relative.
sed -i.bak 's/^import judge_pb2 as judge__pb2/from . import judge_pb2 as judge__pb2/' "$out/judge_pb2_grpc.py"
rm -f "$out"/*.bak

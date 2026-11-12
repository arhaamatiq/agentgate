# AgentGate Go services: gateway, auditor, loadgen, demo MCP server.
# One image, one binary per container (set via `command`).
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/ ./cmd/...

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ /usr/local/bin/
USER nonroot:nonroot
EXPOSE 8080 9102
ENTRYPOINT ["/usr/local/bin/agentgate-gateway"]
CMD ["serve"]

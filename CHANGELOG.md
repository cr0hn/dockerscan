# Changelog

All notable changes to DockerScan are documented here.
Most recent changes appear first.

---

## [Unreleased] - 2026-06-11

### Changed
- Updated OpenTelemetry dependencies:
  - `go.opentelemetry.io/otel`: v1.38.0 → v1.43.0
  - `go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp`: v1.38.0 → v1.43.0
  - `go.opentelemetry.io/otel/metric`: v1.38.0 → v1.43.0
  - `go.opentelemetry.io/otel/trace`: v1.38.0 → v1.43.0
  - `go.opentelemetry.io/otel/sdk`: v1.38.0 → v1.43.0
  - `go.opentelemetry.io/otel/sdk/metric`: added at v1.43.0
  - `go.opentelemetry.io/auto/sdk`: v1.1.0 → v1.2.1
- `github.com/docker/docker`: attempted upgrade to v29.3.1, but that version does not exist in the module proxy. The highest available stable release remains **v28.5.2+incompatible** (no change). Compilation verified successfully with current version.
- Several indirect dependencies upgraded as part of the otel bump:
  - `google.golang.org/grpc`: v1.75.0 → v1.80.0
  - `golang.org/x/sys`: v0.36.0 → v0.42.0
  - `golang.org/x/net`: v0.43.0 → v0.52.0
  - `golang.org/x/text`: v0.28.0 → v0.35.0
  - `go.opentelemetry.io/proto/otlp`: v1.7.1 → v1.10.0
  - `google.golang.org/protobuf`: v1.36.8 → v1.36.11

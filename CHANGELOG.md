# Changelog

All notable changes to DockerScan are documented here.
Most recent changes appear first.

---

## [2026-06-11] - Unit tests for runtime and supplychain scanners

### Added
- `internal/scanner/runtime/runtime_test.go`: table-driven unit tests for all internal check methods of `RuntimeScanner` (privileged mode, capabilities, seccomp, AppArmor, namespaces, read-only rootfs, sensitive mounts, user config) — 30 test cases, no Docker daemon required
- `internal/scanner/supplychain/supplychain_test.go`: table-driven unit tests for all detection logic in `SupplyChainScanner` (miner regex patterns, miner binary filenames, CVE-2024-3094 backdoor library version matching, phishing patterns, suspicious connection patterns, imageless container layer logic) — 37 test cases, no Docker daemon required

---

## [2026-06-11] - Docker credential helpers support

### Added
- `pkg/auth/auth.go`: full support for Docker credential helpers (`credHelpers` per-registry and `credsStore` global) via `github.com/docker/docker-credential-helpers`
- Helpers are resolved before the plain `auths` section, matching Docker CLI priority order
- Docker Hub URLs normalized to `https://index.docker.io/v1/` as required by helpers
- 5-second timeout per helper call to prevent process hangs
- Input validation: `credStoreName` must match `[a-zA-Z0-9_-]+` (path traversal protection)
- Silent fallback to `auths` when helper binary is not installed

### Fixed
- `pkg/auth/auth.go`: warning "credential helper not supported yet" replaced by actual support
- `pkg/auth/auth.go`: `credHelpers` map lookup now tries Docker Hub aliases (`docker.io`, `registry-1.docker.io`) in addition to normalized name

---

## [2026-06-11] - verbose and debug flags

### Added
- `internal/logger/logger.go`: new lightweight logger package with `Verbose()` and `Debug()` functions writing to stderr
- `--verbose` / `-v` flag: shows scan progress (which scanner is running, findings count per scanner, image pull status)
- `--debug` flag: includes everything in verbose mode plus previously-silenced internal errors

### Changed
- `cmd/dockerscan/main.go`: parse `--verbose`/`-v` and `--debug` flags; initialise logger globals; emit verbose messages around image pull and scan lifecycle; updated help text
- `internal/scanner/scanner.go`: emit `logger.Verbose` before/after each scanner run; emit `logger.Debug` when a scanner returns an error (was silently dropped)
- `internal/scanner/cis/cis.go`: `logger.Debug` when `GetImageHistory` or `VerifyImageSignature` fail (were silenced)
- `internal/scanner/supplychain/supplychain.go`: `logger.Debug` for each of the six non-fatal sub-check errors (were silenced with comments only)
- `internal/scanner/runtime/runtime.go`: `logger.Debug` when `scanContainer` fails for a container (was silenced)

### Notes
- Without any flags, behaviour is identical to previous versions (no output change)
- `--debug` implicitly activates verbose output
- All verbose/debug messages go to **stderr** to avoid polluting stdout/JSON pipelines

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

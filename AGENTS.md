# Repository Guidelines

## Project Structure & Module Organization
Go binaries live in `cmd/node` (daemon) and `cmd/cli` (tooling). Domain logic is split across `pkg/`, with `pkg/messaging` handling NATS streams, `pkg/mpc` running threshold flows, and `pkg/security` guarding keys. Configuration templates (`config.yaml.template`, `config.prod.yaml.template`) and scripts sit at the repo root, end-to-end harnesses in `e2e/`, client samples in `examples/`, deployment assets in `deployments/`, and benchmarking utilities in `benchmark/`.

## Build, Test, and Development Commands
- `make build` compiles both binaries ahead of packaging.
- `make mpc-node` / `make mpc-cli` install the tools into `GOBIN`.
- `make test` runs `go test ./...`; set `GOFLAGS=-race` if race checks matter.
- `make test-coverage` emits `coverage.out` and `coverage.html`.
- `make e2e-test` executes the Docker flows in `e2e/`; rerun after messaging, identity, or config edits.
- `make cleanup-test-env` removes leftover containers; the same logic lives in `e2e/cleanup_test_env.sh`.

## Coding Style & Naming Conventions
Target Go 1.23+. Keep files formatted with `gofmt` (`go fmt ./...`) and imports sorted. Package names stay lower_snake_case (`mpc`, `storage`); exported identifiers use PascalCase. Prefer constructors such as `NewMessageManager` to inject dependencies, colocate config structs in `pkg/config`, and keep logging consistent with helpers in `pkg/logger`. Compose errors with `fmt.Errorf("context: %w", err)` and avoid duplicate logging.

## Testing Guidelines
Place unit tests beside code using table-driven patterns and `TestXxx` names. During iteration, run focused suites such as `go test ./pkg/messaging -run TestStreamManager -count=1`. For cluster checks, prepare identities via `setup_initiator.sh` and `setup_identities.sh`, then call `make e2e-test`, which drives `docker-compose.test.yaml` and `config.test.yaml`. Keep coverage near the baseline from `make test-coverage`, refresh `coverage.out` when behaviour shifts, and add e2e assertions plus log captures for MPC protocol tweaks.

## Commit & Pull Request Guidelines
Commits follow Conventional Commit prefixes (`feat:`, `fix:`, `refactor:`) as seen in `git log`; keep messages imperative and scoped (e.g., `feat: Add badger encryption guard`). Pull requests should outline purpose, link related issues, and confirm validation (`make test`, `make e2e-test`, optional `go vet`). Attach screenshots or logs for CLI or UX changes, flag deployment or config impacts, and ping maintainers of affected packages with rollback notes.

## Security & Configuration Tips
Do not commit secrets; store live values in environment variables or `age`-encrypted files, using the `*.template` sources for defaults. Review `SECURITY.md` and `pkg/security` before altering messaging or identity flows. When key schemas change, rebuild identities with `setup_initiator.sh` and `setup_identities.sh`, validate via `go run ./cmd/cli config validate --file config.yaml`, and synchronize any deployment updates (`deployment_script.sh`, `deployments/systemd`).

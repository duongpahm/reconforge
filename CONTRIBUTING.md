# Contributing

ReconForge is a terminal-first reconnaissance framework. This document defines the minimum engineering bar for code changes, new modules, release work, and documentation updates.

## Project layout

- `cmd/reconforge`: CLI entrypoints and user-facing commands.
- `internal/orchestrator`: scan lifecycle, checkpointing, and stage execution.
- `internal/engine`: DAG pipeline, executor, state handling, and panic recovery.
- `internal/module`: reconnaissance modules grouped by phase.
- `internal/runner`: local and SSH-backed tool execution.
- `internal/tools`: external tool registry, installation, and checksum validation.
- `internal/ui`: terminal UX and TUI dashboard components.
- `configs/`: default config and scan profiles.
- `test/e2e`: smoke coverage for CLI-level flows.

## Development environment

1. Install Go using the version declared in `go.mod`.
2. Clone the repository and work from the `reconforge/` root.
3. Install `pre-commit` if you want local hook enforcement.
4. Keep a writable `GOCACHE` and `GOMODCACHE` available for local test runs.

Suggested bootstrap:

```bash
go version
go test ./...
go vet ./...
pre-commit install
```

## Daily workflow

1. Start from `main` and create a short-lived branch.
2. Make the smallest coherent change that solves one problem.
3. Run focused tests first, then rerun repo-wide verification.
4. Review your own diff before opening a PR.
5. Update docs when the CLI surface, config schema, or release flow changes.

Expected verification for most code changes:

```bash
go build ./...
go test ./...
go vet ./...
```

When touching concurrency, shared state, or the orchestrator, also run:

```bash
go test -race ./...
```

## Code style

- Keep code `gofmt` clean.
- Prefer explicit error wrapping with actionable context.
- Keep module behavior deterministic where possible.
- Avoid silent failures unless the module is intentionally non-fatal and logs why.
- Do not hide external tool errors if they block the user from scanning.
- Add comments only when the code would otherwise be ambiguous.

## Testing policy

- Add or update tests for every behavior change.
- Prefer targeted unit tests over broad snapshot tests.
- For module packages, test both `Validate()` and at least one meaningful `Run()` path.
- For CLI flags, verify wiring and user-visible behavior.
- For configuration changes, add a load/merge test.
- For release or packaging changes, verify generated artifacts when the tooling is available.

Coverage guidance:

- Maintain or improve package coverage when touching existing code.
- New module or runner behavior should not land with zero direct test coverage.
- CI records coverage output even when local coverage tooling is limited by the environment.

## Pre-commit hooks

The repository includes `.pre-commit-config.yaml` with:

- YAML sanity checks
- whitespace and EOF normalization
- `gofmt`
- `go vet ./...`
- `go test ./...`

Install and use it locally:

```bash
pre-commit install
pre-commit run --all-files
```

## Pull requests

- Keep PRs focused and reviewable.
- Explain the user-facing effect, risks, and verification steps.
- Mention if local verification was blocked by environment issues.
- Link related issues, audits, or execution-plan tasks when relevant.
- Do not mix unrelated refactors into a bug fix.

Commit message guidance:

- `fix: recover module panic in executor`
- `test: cover osint/web/vuln run paths`
- `docs: add changelog and contribution guide`

## Adding a new module

Before adding a module, read [ARCHITECTURE.md](./ARCHITECTURE.md) and inspect the closest existing package in `internal/module/`.

Checklist:

1. Pick the correct phase and dependencies.
2. Keep `Name()` stable and unique.
3. Return required binaries from `RequiredTools()`.
4. Make `Validate()` fail fast when config disables the module.
5. Decide whether runtime failure is fatal or best-effort.
6. Add at least one focused test for the execution path.
7. Wire the module into the orchestrator pipeline if it is intended to run.

Minimal module template:

```go
type ExampleModule struct{}

func (m *ExampleModule) Name() string            { return "example_module" }
func (m *ExampleModule) Description() string     { return "Example reconnaissance module" }
func (m *ExampleModule) Phase() engine.Phase     { return engine.PhaseWeb }
func (m *ExampleModule) Dependencies() []string  { return []string{"httpx_probe"} }
func (m *ExampleModule) RequiredTools() []string { return []string{"exampletool"} }

func (m *ExampleModule) Validate(cfg *config.Config) error {
	if !cfg.Web.Enabled {
		return fmt.Errorf("example module disabled")
	}
	return nil
}

func (m *ExampleModule) Run(ctx context.Context, scan *module.ScanContext) error {
	result, err := scan.Runner.Run(ctx, "exampletool", []string{"-d", scan.Target}, runner.RunOpts{})
	if err != nil {
		return fmt.Errorf("exampletool: %w", err)
	}
	_ = result
	return nil
}
```

## Adding a new external tool

When you add or change an entry in the tool registry:

1. Set a clear install source.
2. Populate `DocsURL` so missing-tool errors can point users somewhere useful.
3. Add `SHA256` when you have a stable published checksum.
4. Verify that install and post-install checks still pass.
5. Ensure the tool name matches what modules actually invoke.

Notes on integrity:

- ReconForge records a checksum manifest for installed tools and uses it to detect tampering.
- The first verified install establishes the manifest entry when no vendor checksum is available.
- If you rotate a checksum intentionally, update the registry entry and document why in the PR.

## Secrets and configuration hygiene

- Prefer environment indirection such as `${RECONFORGE_NOTIFY_SLACK_WEBHOOK}` over plaintext secrets.
- `reconforge init` writes config files with mode `0600`.
- `reconforge doctor` warns when secret-bearing configs are too permissive.
- `reconforge config show` masks secret fields before printing them.

Do not:

- commit real webhooks, tokens, or API keys
- paste production secrets into issue comments or PRs
- add sample configs with live credentials

## Release workflow

Release work uses `.goreleaser.yml` and Git tags.

Normal sequence:

```bash
go test ./...
go vet ./...
make manpages
goreleaser check
goreleaser release --snapshot --clean
git tag -a v0.1.0-alpha -m "Release message"
git push origin main
git push origin v0.1.0-alpha
```

Release expectations:

- artifacts include checksums
- `checksums.txt` has a detached signature
- version metadata is embedded into binaries
- generated man pages are packaged with the release archives
- GitHub Actions release workflow expects these secrets:
  - `RECONFORGE_GPG_PRIVATE_KEY`
  - `RECONFORGE_GPG_PASSPHRASE`
  - `RECONFORGE_GPG_FINGERPRINT`

## Documentation updates

Update the relevant docs when changing:

- release flow: [CHANGELOG.md](./CHANGELOG.md) and this file
- release runbook: [RELEASE_CHECKLIST.md](./RELEASE_CHECKLIST.md)
- architecture or execution model: [ARCHITECTURE.md](./ARCHITECTURE.md)
- user-visible commands or profiles: `README.md`

When cutting a release:

1. Move user-visible changes from notes into `CHANGELOG.md`.
2. Keep the `Unreleased` section open for the next cycle.
3. Mention breaking config or workflow changes explicitly.

## Review checklist

Before requesting review, confirm:

- code is formatted
- tests cover the changed behavior
- repo-wide verification was run or the blocker is documented
- pipeline wiring matches module registration
- docs reflect new flags, profiles, or release behavior

## Where to start

If you are new to the repository, read these in order:

1. [README.md](./README.md)
2. [ARCHITECTURE.md](./ARCHITECTURE.md)
3. [CHANGELOG.md](./CHANGELOG.md)
4. this contributing guide

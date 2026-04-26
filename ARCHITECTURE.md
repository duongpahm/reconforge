# Architecture

ReconForge is a terminal-first reconnaissance framework built around a staged DAG executor. The CLI prepares targets and configuration, the orchestrator builds a pipeline, modules execute through a shared scan context, and results accumulate into findings and export flows.

## Core layers

- `cmd/reconforge`: parses flags, validates inputs, and maps runtime errors to exit codes.
- `internal/config`: loads defaults, user config, environment overrides, and scan profiles.
- `internal/orchestrator`: translates scan mode plus config into a concrete pipeline.
- `internal/engine`: executes stages and modules with dependency ordering and checkpoint support.
- `internal/module/*`: phase-specific reconnaissance logic grouped into `osint`, `subdomain`, `web`, and `vuln`.
- `internal/runner`: wraps local subprocess execution and SSH-based execution.
- `internal/findings`, `internal/report`, `internal/project`: persistence and reporting surfaces.
- `internal/ui`: terminal output helpers and the Bubble Tea dashboard.

## Execution model

1. The CLI validates targets and loads config plus optional profile overlays.
2. The orchestrator creates a `module.ScanContext` with runner, logger, config, cache, and shared results.
3. The pipeline executor schedules stages respecting declared dependencies.
4. Modules write to `ScanResults`, which later stages consume.
5. Findings and artifacts are persisted, exported, or resumed from checkpoints as needed.

## Error model

- Config and usage errors fail fast at the CLI boundary.
- Missing tool errors are actionable and may be skipped when the user opts in.
- Module panics are recovered in the executor and converted into stage failures.
- Context cancellation propagates back to the CLI so interrupts can exit cleanly.

## Design constraints

- Terminal-first UX: no API server dependency for standard use.
- External-tool orchestration: many modules are wrappers around established security tooling.
- Best-effort modules are allowed, but must log clearly when they degrade.
- Shared mutable scan state must remain thread-safe.

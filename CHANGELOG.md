# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and the project uses Semantic Versioning for tags when practical.

## [Unreleased]

### Added
- Ongoing release and CI hardening.

## [0.1.0-beta] - 2026-04-26

### Added
- CI workflow for build, vet, test, race, and coverage reporting.
- Release workflow for tagged builds through GoReleaser.
- Bundled `stealth` and `deep` scan profiles.
- TUI tests and `NO_COLOR` support verification.
- Architecture and contributor documentation.
- Workflow and pipe-oriented recipe documentation.

### Changed
- Expanded module execution coverage for `osint`, `web`, and `vuln` packages.
- GoReleaser archives now package generated man pages and core docs.
- Release workflow now imports a signing key and CI enforces minimum coverage.

## [0.1.0-alpha] - 2026-04-26

### Added
- Terminal-first reconnaissance CLI with multi-target scan modes.
- DAG-based pipeline executor with checkpointing and resume support.
- OSINT, subdomain, web, and vulnerability scanning module registry.
- Findings storage, export formats, and deduplication helpers.
- Tool installer, doctor command, and self-update flow with checksum verification.
- Bubble Tea dashboard and tailing workflows.
- Shell completion and hidden manpage generation command.

### Changed
- Initial alpha stabilization focused on pipeline wiring, missing-tool handling, and release hygiene.

### Removed
- Legacy API-server-oriented components not aligned with the terminal-first direction.

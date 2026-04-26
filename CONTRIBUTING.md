# Contributing

## Release hygiene

- Keep `LICENSE` and release metadata in sync with README claims.
- Release artifacts are expected to be built with GoReleaser and accompanied by `checksums.txt` plus a detached `checksums.txt.sig`.
- The release signing public key fingerprint is documented in `README.md`.

## Tool registry

- New entries in `internal/tools/manager.go` should include a `DocsURL`.
- If you have a stable published checksum for the installed binary, set `SHA256`.
- If no vendor checksum exists yet, ReconForge records the checksum from the first verified install and uses that manifest to detect tampering later.

## Secrets

- Prefer environment variables such as `RECONFORGE_EXPORT_NOTIFY_SLACK_WEBHOOK` over plaintext values in config files.
- `reconforge init` writes config files with mode `0600`.
- `reconforge doctor` warns when a config file with secrets is broader than `0600`.

# Release Checklist

Use this checklist before pushing a release tag such as `v0.1.0-beta` or `v0.1.0`.

## GitHub repository settings

- `Actions` enabled for the repository
- `Contents: Read and write` allowed for workflows
- Tag pushes allowed from the release operator

## Required GitHub secrets

- `RECONFORGE_GPG_PRIVATE_KEY`
- `RECONFORGE_GPG_PASSPHRASE`
- `RECONFORGE_GPG_FINGERPRINT`

## Local verification

```bash
go build ./...
go test ./...
go vet ./...
go test -race ./...
```

## Release dry-run

```bash
goreleaser check
goreleaser release --snapshot --clean
```

## Artifact expectations

- archives for `linux` and `darwin`
- `checksums.txt`
- `checksums.txt.sig`
- embedded version and build time
- packaged man pages

## Before tagging

- `CHANGELOG.md` updated
- `README.md` links valid
- `CONTRIBUTING.md` reflects current release flow
- release signing key fingerprint documented in `README.md`

## Tag and push

```bash
git tag -a v0.1.0-beta -m "Beta release"
git push origin main
git push origin v0.1.0-beta
```

## After pushing

- confirm CI workflow passes on `main`
- confirm release workflow starts for the new tag
- confirm GitHub release has archives, checksum, and signature

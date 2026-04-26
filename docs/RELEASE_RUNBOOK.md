# ReconForge Release Runbook

> Quy trình chi tiết để release version mới (alpha → beta → stable).
> Tham chiếu nhanh: [`RELEASE_CHECKLIST.md`](../RELEASE_CHECKLIST.md).

---

## 0. Phân loại release

| Tag pattern | Audience | Frequency |
|-------------|----------|-----------|
| `v0.X.0-alpha` | Internal test, breaking changes | Weekly |
| `v0.X.0-rc1`, `rc2`, ... | Public preview, freeze features | Per beta |
| `v0.X.0-beta` | Public, no feature lock | Monthly |
| `v0.X.0` | Stable, semantic versioning | Quarterly |
| `v0.X.Y` | Patch (bugfix only) | As needed |

Mỗi major bump (`v0.X` → `v0.X+1`) tag pre-release `alpha → rc → beta → stable` trước khi promote.

---

## 1. One-time setup (làm 1 lần cho repository)

### 1.1. Generate GPG release key

Key dùng để sign `checksums.txt` — user `reconforge self-update` verify trước khi replace binary.

```bash
# Generate keypair (chọn ECC curve25519 — modern, fast)
gpg --quick-generate-key "ReconForge Release <release@reconforge.dev>" \
    ed25519 sign 2y

# Lấy fingerprint
gpg --list-keys --with-colons release@reconforge.dev | \
    awk -F: '/^fpr:/ {print $10; exit}'
# → ví dụ: 3AA5C34371567BD2

# Export public key (commit vào repo hoặc upload keyserver)
gpg --armor --export release@reconforge.dev > docs/release-pubkey.asc

# Export private key (CHỈ dùng cho GitHub Secrets, KHÔNG commit)
gpg --armor --export-secret-keys release@reconforge.dev > /tmp/release-private.key
```

**⚠️ Bảo mật:**
- Lưu `/tmp/release-private.key` vào password manager (1Password, Bitwarden), xoá khỏi disk: `shred -u /tmp/release-private.key`
- Backup offline (USB encrypted, paper backup) — mất key = không release được

### 1.2. Upload public key (optional, recommend)

```bash
gpg --send-keys 3AA5C34371567BD2 --keyserver hkps://keys.openpgp.org
```

### 1.3. Embed public key + fingerprint vào codebase

```bash
# Copy pubkey vào internal/selfupdate hoặc config dir
cp docs/release-pubkey.asc internal/release/release-pubkey.asc

# Update README.md với fingerprint
echo "GPG fingerprint: 3AA5C34371567BD2" >> README.md
```

### 1.4. Setup GitHub repository secrets

Repository → **Settings** → **Secrets and variables** → **Actions** → **New repository secret**:

| Secret name | Value |
|-------------|-------|
| `RECONFORGE_GPG_PRIVATE_KEY` | Nội dung file `release-private.key` (full ASCII armored) |
| `RECONFORGE_GPG_PASSPHRASE` | Passphrase nhập khi tạo key (nếu có) |
| `RECONFORGE_GPG_FINGERPRINT` | `3AA5C34371567BD2` |

### 1.5. Repository settings

- **Settings → Actions → General**:
  - ✅ Allow all actions and reusable workflows
  - ✅ Workflow permissions: **Read and write permissions**
  - ✅ Allow GitHub Actions to create and approve pull requests

- **Settings → Branches → Branch protection** (recommend cho `main`):
  - ✅ Require pull request before merging
  - ✅ Require status checks: `test`, `lint`, `security`, `build`
  - ✅ Require linear history

---

## 2. Pre-release verification (every release)

### 2.1. Sync với main

```bash
git checkout main
git pull origin main
git status                    # phải clean
```

### 2.2. Local build + test

```bash
# Build với version từ git
make build
./bin/reconforge version      # version từ git tag

# Full test suite
go vet ./...
go test ./...
go test -race ./...           # cần ≥ 30s, no leak

# Coverage (optional, slow)
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out | tail -1
# expect: total: (statements) ≥ 60%
```

### 2.3. Manual smoke test

```bash
# Dry-run scan
./bin/reconforge scan -d example.com --dry-run --skip-missing-tools 2>&1 | tail -20
echo $?    # 0

# Edge cases
./bin/reconforge scan -d "999.999.999.999" 2>&1
echo $?    # 1 (UsageError)

./bin/reconforge scan -d "" 2>&1
echo $?    # 1

# Signal handling
./bin/reconforge scan -d example.com --profile full --skip-missing-tools &
PID=$!
sleep 3
kill -INT $PID
wait $PID
echo $?    # 130

# Resume
./bin/reconforge scan -d example.com --resume --dry-run

# Tools check
./bin/reconforge doctor

# NO_COLOR
NO_COLOR=1 ./bin/reconforge findings list -t example.com 2>&1 | head -5
# không có ANSI escape code
```

### 2.4. Goreleaser dry-run

```bash
# Verify config
goreleaser check
# expect: ✓ config is valid

# Local snapshot build (không push)
goreleaser release --snapshot --clean
ls dist/
# expect: 4 binary archives + checksums.txt + checksums.txt.sig

# Verify binary
tar -tzf dist/reconforge_*_linux_amd64.tar.gz | head
file dist/reconforge_*_linux_amd64/reconforge
```

### 2.5. Update CHANGELOG.md

```bash
# Edit CHANGELOG.md
$EDITOR CHANGELOG.md

# Format theo Keep a Changelog:
# ## [X.Y.Z] - YYYY-MM-DD
# ### Added
# - feature A (#PR_NUM)
# ### Changed
# - behavior B (#PR_NUM)
# ### Fixed
# - bug C (#PR_NUM)

# Move "Unreleased" section content xuống version mới
```

### 2.6. Update README badges (nếu có version reference)

```bash
# Check README có hardcoded version không
grep -n "v0\." README.md
# Update nếu cần
```

---

## 3. Release execution

### 3.1. Tag annotated

```bash
# Get version next
LAST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
echo "Last tag: $LAST_TAG"

# Tag (annotated, signed)
NEW_TAG="v0.1.0-rc1"
git tag -a "$NEW_TAG" -s -m "Release $NEW_TAG

- Phase 1: Release blockers (LICENSE, goreleaser, signing)
- Phase 2: Robustness (signal, panic, validation)
- Phase 3: Test coverage + CI/CD
- Phase 4: Polish (profiles, manpages, NO_COLOR)

See CHANGELOG.md for details."

# Verify tag
git tag -v "$NEW_TAG"          # phải verify được signature
git show "$NEW_TAG" | head
```

### 3.2. Push tag

```bash
git push origin main
git push origin "$NEW_TAG"
```

### 3.3. Monitor CI workflow

```bash
# Trên GitHub UI: Actions → Release workflow
# Hoặc qua gh CLI:
gh run watch
gh run list --workflow=release.yml --limit 5
```

**Expected sequence:**
1. ✓ checkout
2. ✓ setup-go
3. ✓ import GPG key
4. ✓ goreleaser check
5. ✓ goreleaser release --clean
6. ✓ create GitHub release với artifacts

**Total time:** ~5-10 min cho 4 binary build.

### 3.4. Verify GitHub release page

```bash
gh release view "$NEW_TAG"
# hoặc browser: https://github.com/duongpahm/reconforge/releases/tag/v0.1.0-rc1
```

**Checklist:**
- [ ] 4+ binary archive (linux/darwin × amd64/arm64)
- [ ] `checksums.txt` file
- [ ] `checksums.txt.sig` file (GPG signature)
- [ ] Release notes auto-generated từ commit messages
- [ ] Pre-release flag đúng (rc/alpha = prerelease, stable = không)

---

## 4. Post-release verification

### 4.1. Download + verify checksums

```bash
TAG="v0.1.0-rc1"
URL="https://github.com/duongpahm/reconforge/releases/download/$TAG"

mkdir -p /tmp/release-verify && cd /tmp/release-verify

curl -L -o checksums.txt "$URL/checksums.txt"
curl -L -o checksums.txt.sig "$URL/checksums.txt.sig"
curl -L -o reconforge.tar.gz "$URL/reconforge_${TAG#v}_darwin_arm64.tar.gz"

# Verify GPG sig
gpg --verify checksums.txt.sig checksums.txt
# expect: Good signature from "ReconForge Release ..."

# Verify SHA256
shasum -a 256 -c checksums.txt --ignore-missing
# expect: reconforge_*_darwin_arm64.tar.gz: OK

# Extract + run
tar xzf reconforge.tar.gz
./reconforge_*/reconforge version
```

### 4.2. Test self-update từ binary cũ

```bash
# Giả lập user có binary cũ
cp /usr/local/bin/reconforge /tmp/reconforge-old
/tmp/reconforge-old self-update --check
# expect: thấy version mới
/tmp/reconforge-old self-update
# expect: download + verify SHA256 + verify GPG → replace binary
/tmp/reconforge-old version
# expect: version mới
```

### 4.3. Smoke test trên fresh install

```bash
# Fresh user simulation
docker run --rm -it ubuntu:22.04 bash -c '
  apt update && apt install -y curl
  curl -L https://github.com/duongpahm/reconforge/releases/download/v0.1.0-rc1/reconforge_0.1.0-rc1_linux_amd64.tar.gz | tar xz
  ./reconforge_*/reconforge init --yes
  ./reconforge_*/reconforge doctor
  ./reconforge_*/reconforge scan -d example.com --dry-run --skip-missing-tools 2>&1 | tail -5
'
```

---

## 5. Rollback procedure

### 5.1. Rollback chưa publish (CI failed)

```bash
# Xoá tag local + remote
git tag -d "$NEW_TAG"
git push origin ":refs/tags/$NEW_TAG"

# Fix code, retag
git tag -a "$NEW_TAG" -m "Re-tag after fix"
git push origin "$NEW_TAG"
```

### 5.2. Rollback đã publish (binary có lỗi nghiêm trọng)

```bash
# Mark release as draft (hidden khỏi user)
gh release edit "$NEW_TAG" --draft

# Hoặc delete hoàn toàn
gh release delete "$NEW_TAG"
git tag -d "$NEW_TAG"
git push origin ":refs/tags/$NEW_TAG"

# Hotfix
git checkout -b hotfix/$NEW_TAG
# ... fix code ...
git commit -am "fix: critical bug in $NEW_TAG"
git checkout main
git merge hotfix/$NEW_TAG

# Bump patch version
git tag -a "v0.1.1" -s -m "Hotfix v0.1.1"
git push origin main v0.1.1
```

### 5.3. Notify users

- Pin issue: "Critical bug in v0.1.0-rc1 — please upgrade to v0.1.1"
- Discord/Twitter notification
- Update README.md với warning

---

## 6. Promote pre-release → stable

Khi release `v0.1.0-rc1` đã soak ≥ 7 ngày, không có bug critical:

```bash
# Tag stable (cùng commit với rc cuối cùng)
git tag -a "v0.1.0" -s -m "Stable release v0.1.0

Promoted from v0.1.0-rc1 after 7-day soak.
No critical issues reported."
git push origin v0.1.0

# Verify CI re-runs
gh run watch

# Promote release page
gh release edit v0.1.0 --prerelease=false
```

---

## 7. Common issues + troubleshooting

### Issue: GPG sign failed in CI

```
gpg: signing failed: No secret key
```

**Fix:** Verify `RECONFORGE_GPG_PRIVATE_KEY` secret là **full ASCII armored** content, bao gồm:
```
-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----
```

### Issue: Goreleaser version mismatch

```
goreleaser check failed: requires version v2+
```

**Fix:** `.goreleaser.yml` đầu file phải có `version: 2`.

### Issue: Tag conflict

```
fatal: tag 'v0.1.0-rc1' already exists
```

**Fix:** Xoá tag cũ (xem 5.1).

### Issue: Self-update GPG verify fail trên user machine

```
✗ GPG verification failed: signature does not match
```

**Fix:** Verify embedded pubkey trong binary khớp với key dùng sign. Nếu key rotation → cần migration release.

---

## 8. Reference

- [`RELEASE_CHECKLIST.md`](../RELEASE_CHECKLIST.md) — Quick checklist version
- [`CHANGELOG.md`](../CHANGELOG.md) — Release notes
- [`.goreleaser.yml`](../.goreleaser.yml) — Build config
- [`.github/workflows/release.yml`](../.github/workflows/release.yml) — CI workflow
- [GoReleaser docs](https://goreleaser.com/) — Tool documentation
- [Keep a Changelog](https://keepachangelog.com/) — CHANGELOG format

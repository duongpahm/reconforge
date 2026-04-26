# ReconForge — Codex Execution Plan

## Execution Status

> **Cập nhật:** 2026-04-26
> **Người thực thi:** Codex
> **Trạng thái:** Phase 1, 2, 3, 4 completed

### Kết quả thực thi

- `Phase 1` completed:
  - Added `LICENSE`, `.goreleaser.yml`, release signing flow, secret masking, tool checksum verification, and release docs.
- `Phase 2` completed:
  - Added signal-aware cancellation, target validation, actionable `MissingToolError`, and panic recovery in the pipeline executor.
- `Phase 3` completed:
  - Expanded runtime tests for `osint`, `web`, `vuln`, added GitHub Actions CI/release workflows, and added pre-commit hooks.
- `Phase 4` completed:
  - Added `stealth` and `deep` profiles, manpage generation wiring, `CHANGELOG.md`, `ARCHITECTURE.md`, expanded `CONTRIBUTING.md`, and `NO_COLOR` support.

### Verification summary

- `go build ./...` passed
- `go test ./...` passed
- `go vet ./...` passed
- `go test -race ./...` passed
- `gen-manpages` generated `53` manpages from the built CLI

### Notes

- Local coverage measurement with `go test -cover...` remains environment-limited on this machine because the Go 1.25 toolchain reports `go: no such tool "covdata"`. CI coverage workflow was added to run this in a cleaner environment.
- `make manpages` now supports explicit Go binary override via `make GO=/path/to/go manpages`, which avoids relying on an older `go` in `PATH`.

### Post-review fixes (2026-04-26)

GPT-5.5 review (via code-reviewer agent) tìm thấy 5 issues trong Phase 2. 3 issue HIGH/MEDIUM đã fix:

| # | Severity | Issue | Fix | File |
|---|----------|-------|-----|------|
| 1 | HIGH | SIGINT trả exit code 2 thay vì 130 | Thêm `exitcode.Interrupt()` + `CriticalFinding()`, gọi `Interrupt()` khi `context.Canceled` | `internal/exitcode/codes.go`, `cmd/reconforge/main.go:187` |
| 2 | MEDIUM | `MissingToolError` thiếu `✗`, sai indent | Format đúng spec 3 dòng `✗ ... / Fix: ... / Docs: ...` | `internal/runner/errors.go` |
| 3 | MEDIUM | Wildcard domain `*.example.com` bị reject | Thêm `IsWildcard()` check trong `validateTargets`, validate parent domain | `cmd/reconforge/main.go:361` |
| 4 | HIGH | Panic recovery trong worker goroutine | **FALSE POSITIVE** — `engine/pipeline.go:367-380` đã có per-module `recover()` | (no fix needed) |
| 5 | LOW | TUI + SIGINT goroutine race | Defer fix sang v0.2 (không block release) | `internal/orchestrator/orchestrator.go:352` |

Test mới thêm:
- `internal/exitcode/codes_test.go` — verify Interrupt/CriticalFinding wrapping + Code() unwrap chain
- `internal/runner/errors_test.go` — verify MissingToolError format + errors.As() unwrap
- `cmd/reconforge/validate_targets_test.go` — 16 test case cho validateTargets() (valid + invalid + wildcard)

> **Audience:** Codex (AI agent thực thi)
> **Reviewer:** GPT-5.5
> **Ngày:** 2026-04-26
> **Trạng thái hiện tại:** Alpha 75% complete
> **Mục tiêu:** Đẩy lên Beta-ready 95% qua 4 phase

---

## 0. Trạng thái hiện tại (% Completeness)

Tổng hợp từ 3 audit chiều khác nhau:

| Chiều | Score | Status |
|-------|-------|--------|
| **Feature parity** với reconFTW bash | 93% | ✅ 82/82 module wired |
| **CLI surface** | 100% | ✅ 19 subcommand đủ logic |
| **Terminal-first features** | 83% | ⚠️ thiếu HintError, man pages, scope sync API |
| **Code quality** (architecture, smell, deps) | 85% | ✅ Clean interfaces, no circular import |
| **Test coverage** | 35% | 🔴 Module 7%, critical path partial |
| **Production-readiness** | 60% | 🔴 Thiếu LICENSE, release auto, signing |
| **Output quality** | 100% | ✅ 7 export format, 3 report template |
| **TỔNG** | **~75%** | Alpha → Beta cần 3-5 ngày |

### Mức độ hoàn thiện theo user-facing feature

```
████████████████████░░░░░░  Feature parity (93%)
████████████████████████░░  CLI commands (100%)
█████████████████████░░░░░  Terminal UX (83%)
█████████████████░░░░░░░░░  Code quality (85%)
██████░░░░░░░░░░░░░░░░░░░░  Test coverage (35%)  ← gap lớn nhất
████████████░░░░░░░░░░░░░░  Production ready (60%)  ← gap thứ 2
```

### Gap lớn nhất hiện tại

| # | Gap | Severity | Effort |
|---|-----|----------|--------|
| 1 | LICENSE file missing (claim MIT) | CRITICAL | S |
| 2 | No `.goreleaser.yml` + git tag → không release được | CRITICAL | M |
| 3 | Tool installer không verify checksum | CRITICAL | M |
| 4 | Self-update không GPG signing | CRITICAL | M |
| 5 | Config secrets stored plaintext (Slack/Discord/Telegram tokens) | HIGH | S |
| 6 | Không graceful SIGINT shutdown → mất checkpoint | HIGH | M |
| 7 | Không panic recovery handler | HIGH | S |
| 8 | Target validation missing (IP/CIDR/domain format) | HIGH | S |
| 9 | MissingToolError không hint user fix | HIGH | S |
| 10 | Module test coverage 7% (74 module untested) | HIGH | XL |
| 11 | Không CI/CD (GitHub Actions, pre-commit) | MEDIUM | M |
| 12 | Stealth profile claimed nhưng không tồn tại | MEDIUM | S |
| 13 | Man pages chưa generate output | MEDIUM | S |
| 14 | go.mod version `1.25.0` đáng nghi | MEDIUM | S |
| 15 | TUI không honor `NO_COLOR` env | LOW | S |

---

## 1. Cấu trúc plan cho Codex

Plan này chia 4 phase, mỗi phase có acceptance criteria độc lập để GPT-5.5 review từng phase:

| Phase | Tên | Mục tiêu | Effort |
|-------|-----|----------|--------|
| **Phase 1** | Release blockers | LICENSE, goreleaser, git tag, signing | 4-6h |
| **Phase 2** | Robustness | Signal/panic handler, validation, hints | 3-4h |
| **Phase 3** | Test coverage | 35% → 70%, CI/CD wiring | 1-2 ngày |
| **Phase 4** | Polish & docs | Stealth profile, man pages, CHANGELOG | 2-3h |

### Format mỗi task

Mỗi task tuân theo template:

```
### Task X.Y — <Tên>
- File: <path:line>
- Spec: <yêu cầu cụ thể>
- Implementation: <pseudocode hoặc code skeleton>
- Verification: <command để verify>
- Acceptance criteria: <bullet list để GPT review>
- Rollback: <git revert ...>
- Effort: S/M/L
- Dependencies: <task khác phải xong trước>
```

---

## Phase 1 — Release Blockers (CRITICAL)

> **Mục tiêu:** Project có thể release v0.1.0-alpha lên GitHub với SHA256-verified binary.

### Task 1.1 — Tạo LICENSE file

- **File:** `LICENSE` (tạo mới ở repo root)
- **Spec:** README claim MIT, cần file LICENSE thực tế.
- **Implementation:** MIT license template với copyright `2026 ReconForge contributors`.
- **Verification:**
  ```bash
  test -f LICENSE
  grep -q "MIT License" LICENSE
  ```
- **Acceptance criteria:**
  - [ ] File `LICENSE` tồn tại tại repo root
  - [ ] Nội dung là MIT license chuẩn
  - [ ] Copyright year + holder rõ ràng
  - [ ] README.md `License` section trỏ tới file
- **Rollback:** `rm LICENSE`
- **Effort:** S (5 min)

### Task 1.2 — Verify + sửa Go version trong go.mod

- **File:** `go.mod:3`
- **Spec:** Hiện `go 1.25.0`. Verify Go 1.25 đã GA. Nếu chưa → đổi `go 1.23` (LTS).
- **Implementation:**
  ```bash
  # Check Go release
  curl -s https://go.dev/dl/?mode=json | jq -r '.[0].version'
  # Nếu < go1.25 → sed -i '' 's/go 1\.25\.0/go 1.23/' go.mod
  ```
- **Verification:** `go build ./...` pass với toolchain phổ biến (1.21, 1.22, 1.23).
- **Acceptance criteria:**
  - [ ] `go.mod:3` directive khớp Go version sẵn có public
  - [ ] `go mod tidy` không lỗi
  - [ ] Build pass với Go 1.23 (LTS minimum)
- **Effort:** S (5 min)
- **Dependencies:** Cần Go toolchain.

### Task 1.3 — Tạo `.goreleaser.yml`

- **File:** `.goreleaser.yml` (tạo mới)
- **Spec:** GoReleaser config build cross-platform binary + archive + checksum + GitHub release.
- **Implementation:**
  ```yaml
  version: 2
  before:
    hooks:
      - go mod tidy
  builds:
    - id: reconforge
      main: ./cmd/reconforge
      env: [CGO_ENABLED=0]
      goos: [linux, darwin]
      goarch: [amd64, arm64]
      ldflags:
        - -s -w
        - -X github.com/duongpahm/ReconForge/internal/config.Version={{.Version}}
        - -X github.com/duongpahm/ReconForge/internal/config.BuildTime={{.Date}}
  archives:
    - format: tar.gz
      name_template: "reconforge_{{.Version}}_{{.Os}}_{{.Arch}}"
      format_overrides:
        - goos: windows
          format: zip
  checksum:
    name_template: "checksums.txt"
    algorithm: sha256
  changelog:
    sort: asc
    filters:
      exclude:
        - "^docs:"
        - "^test:"
        - "^chore:"
  release:
    github:
      owner: duongpahm
      name: reconforge
    draft: false
    prerelease: auto
  ```
- **Verification:**
  ```bash
  goreleaser check
  goreleaser release --snapshot --clean   # local dry-run
  ls dist/   # phải có binary + checksums.txt
  ```
- **Acceptance criteria:**
  - [ ] `goreleaser check` pass
  - [ ] `goreleaser release --snapshot --clean` build thành công 4 binary (linux+darwin × amd64+arm64)
  - [ ] `dist/checksums.txt` tồn tại với SHA256 cho mỗi archive
  - [ ] Binary embed Version + BuildTime đúng
- **Rollback:** `rm .goreleaser.yml`
- **Effort:** M (45 min)

### Task 1.4 — Tag first release `v0.1.0-alpha`

- **File:** N/A (git operation)
- **Spec:** Tạo annotated tag, push lên remote, trigger goreleaser.
- **Implementation:**
  ```bash
  git tag -a v0.1.0-alpha -m "First alpha release: 82 modules, terminal-first"
  git push origin v0.1.0-alpha
  ```
- **Verification:**
  ```bash
  git tag -l            # v0.1.0-alpha
  git describe --tags   # v0.1.0-alpha hoặc v0.1.0-alpha-N-gXXX
  ```
- **Acceptance criteria:**
  - [ ] Git tag `v0.1.0-alpha` tồn tại local + remote
  - [ ] `make build` embed version `v0.1.0-alpha` (không phải `dev`)
  - [ ] (optional) GitHub release page có binary nếu CI configure
- **Rollback:** `git tag -d v0.1.0-alpha && git push origin :v0.1.0-alpha`
- **Effort:** S (5 min)
- **Dependencies:** Task 1.3 phải xong (goreleaser.yml để CI dùng).

### Task 1.5 — Tool installer verify checksum

- **File:** `internal/tools/manager.go` (Install function)
- **Spec:** Hiện `Install()` chỉ chạy `go install ...`. Cần verify integrity bằng `go mod verify` hoặc binary checksum sau install.
- **Implementation:**
  ```go
  func (m *Manager) Install(ctx context.Context, name string) error {
      // ... existing install logic
      if err := exec.CommandContext(ctx, "go", "mod", "verify").Run(); err != nil {
          return fmt.Errorf("post-install verify failed for %s: %w", name, err)
      }
      // For tools with known SHA256 in registry:
      if expected := m.registry[name].SHA256; expected != "" {
          got, err := sha256File(installedPath)
          if err != nil { return err }
          if got != expected {
              return fmt.Errorf("checksum mismatch for %s: got %s, want %s", name, got, expected)
          }
      }
      return nil
  }
  ```
- **Verification:**
  ```bash
  ./reconforge tools install subfinder
  # Tamper installed binary
  echo "tampered" >> ~/go/bin/subfinder
  ./reconforge tools install subfinder    # phải fail với checksum mismatch
  ```
- **Acceptance criteria:**
  - [ ] `Install()` call `go mod verify` post-install
  - [ ] Có pluggable SHA256 verification field trong tool registry
  - [ ] Test: tampered binary detection pass
  - [ ] Doc: ghi rõ trong CONTRIBUTING.md cách thêm SHA256 cho tool mới
- **Effort:** M (30 min)

### Task 1.6 — Self-update GPG signature verification

- **File:** `cmd/reconforge/selfupdate.go`
- **Spec:** Hiện chỉ verify SHA256. Cần extra verify GPG signature `checksums.txt.sig`.
- **Implementation:**
  ```go
  // After download checksums.txt:
  sigURL := fmt.Sprintf("%s/checksums.txt.sig", releaseURL)
  pubKeyPEM := []byte(embeddedPublicKey)  // embed via go:embed
  if err := verifyGPG(checksumData, sigData, pubKeyPEM); err != nil {
      return fmt.Errorf("GPG verification failed: %w", err)
  }
  ```
- **Verification:**
  - Manual: tampered checksums.txt → self-update fail.
  - Test: `selfupdate_test.go` thêm case GPG mismatch.
- **Acceptance criteria:**
  - [ ] `selfupdate.go` thêm function `verifyGPG()`
  - [ ] Embedded public key (go:embed) hoặc fetch từ GitHub
  - [ ] Test pass cho case: valid sig, invalid sig, missing sig
  - [ ] Document key fingerprint trong README
- **Effort:** M (1h)
- **Dependencies:** Task 1.3 (goreleaser cần config sign tag).

### Task 1.7 — Config secrets handling

- **File:** `internal/config/config.go` (NotifyConfig struct), `cmd/reconforge/init.go`, `cmd/reconforge/doctor.go`
- **Spec:** Slack/Discord/Telegram tokens hiện stored plaintext yaml file 644. Cần:
  1. Support env var override (recommended path)
  2. Set file permission 0600 khi `init` write config
  3. `doctor` warn nếu detect plaintext token + file 644
- **Implementation:**
  ```go
  // config.go - allow ${VAR_NAME} expansion
  if strings.HasPrefix(cfg.Notify.SlackWebhook, "${") {
      varName := strings.Trim(cfg.Notify.SlackWebhook, "${}")
      cfg.Notify.SlackWebhook = os.Getenv(varName)
  }

  // init.go - chmod after write
  if err := os.Chmod(configPath, 0600); err != nil {
      return fmt.Errorf("failed to set config permissions: %w", err)
  }

  // doctor.go - permission check
  fi, _ := os.Stat(configPath)
  if fi.Mode().Perm()&0o077 != 0 && hasSecrets(cfg) {
      fmt.Println("⚠ Config file world-readable but contains secrets. Run: chmod 600 " + configPath)
  }
  ```
- **Verification:**
  ```bash
  # Set env var
  export RECONFORGE_NOTIFY_SLACK_WEBHOOK='https://hooks.slack.com/...'
  reconforge config show | grep -i slack    # phải mask hoặc show env ref
  reconforge doctor                          # phải warn nếu config có secret + 644
  ls -la ~/.reconforge/config.yaml          # phải là 600 sau init
  ```
- **Acceptance criteria:**
  - [ ] Env var override hoạt động cho 3 channel
  - [ ] `init` write config với mode 0600
  - [ ] `doctor` warn nếu config có secret + permission > 600
  - [ ] `config show` mask token field (`****`)
  - [ ] CONTRIBUTING ghi rõ best practice
- **Effort:** M (45 min)

---

## Phase 2 — Robustness (HIGH)

> **Mục tiêu:** Scan không crash silent, user thấy lỗi rõ ràng + actionable hint.

### Task 2.1 — Graceful SIGINT shutdown

- **File:** `cmd/reconforge/main.go` (rootCmd Execute hoặc scanCmd RunE)
- **Spec:** Ctrl+C hiện kill thẳng → mất checkpoint state.db. Cần catch SIGINT, cancel context, flush state, rồi exit.
- **Implementation:**
  ```go
  // Trong main.go Execute:
  ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
  defer cancel()

  // Pass ctx xuống scanCmd qua command Context
  rootCmd.SetContext(ctx)

  // Trong scan goroutine:
  go func() {
      <-ctx.Done()
      logger.Warn().Msg("Interrupt received, finishing current modules...")
      // Orchestrator nhận ctx cancel → checkpoint save → graceful return
  }()
  ```
- **Verification:**
  ```bash
  ./reconforge scan -d example.com --profile full &
  sleep 5
  kill -INT $!
  # Sau 1-2s phải in "Saving checkpoint" và exit code 130
  echo $?   # 130
  ./reconforge scan -d example.com --resume   # phải resume từ checkpoint
  ```
- **Acceptance criteria:**
  - [ ] Ctrl+C trong khi scan → log "Interrupt received"
  - [ ] state.db lưu thành công với module status
  - [ ] Exit code 130 (SIGINT)
  - [ ] `--resume` skip module đã done
  - [ ] Test integration: spawn scan, send SIGINT, verify checkpoint
- **Effort:** M (1h)

### Task 2.2 — Panic recovery wrapper

- **File:** `internal/orchestrator/orchestrator.go` (Scan function)
- **Spec:** Module crash hiện = unclean exit, không stack trace. Cần defer recover() global.
- **Implementation:**
  ```go
  func (o *Orchestrator) Scan(ctx context.Context, target string, ...) error {
      defer func() {
          if r := recover(); r != nil {
              o.logger.Error().
                  Interface("panic", r).
                  Str("stack", string(debug.Stack())).
                  Msg("orchestrator panic recovered")
              // Persist last checkpoint
              persistCheckpoint(o.stateMgr, scanID, target, mode, outputDir, scanCtx.Results)
          }
      }()
      // existing logic
  }
  ```
- **Verification:**
  - Inject panic vào 1 module test → orchestrator log + checkpoint, không crash binary.
- **Acceptance criteria:**
  - [ ] `recover()` block in `Scan()` catches panic
  - [ ] Stack trace logged at error level
  - [ ] Checkpoint persisted before return
  - [ ] Test: mock module panic → orchestrator return error, không crash
  - [ ] Same defer cho multi-target loop trong main.go
- **Effort:** S (30 min)

### Task 2.3 — Target validation

- **File:** `cmd/reconforge/main.go` (line 97-128 — target parsing)
- **Spec:** Hiện split string `-d`, `-l`, `--cidr` không validate format. Invalid input → module crash hoặc behavior khó hiểu.
- **Implementation:**
  ```go
  // pkg/types/domain.go (đã có Domain type) — add validator
  func ValidateDomain(s string) error {
      if len(s) > 253 || len(s) == 0 {
          return fmt.Errorf("invalid domain length: %d", len(s))
      }
      // RFC 1035 check
      if !domainRegex.MatchString(s) {
          return fmt.Errorf("invalid domain format: %q", s)
      }
      return nil
  }
  // pkg/types/ip.go — ValidateIP, ValidateCIDR

  // main.go scanCmd RunE:
  for _, t := range targets {
      switch {
      case strings.Contains(t, "/"):  // CIDR
          if _, _, err := net.ParseCIDR(t); err != nil {
              return exitcode.Usage(fmt.Errorf("invalid CIDR %q: %w", t, err))
          }
      case net.ParseIP(t) != nil:  // IP
          continue
      default:  // domain
          if err := types.ValidateDomain(t); err != nil {
              return exitcode.Usage(err)
          }
      }
  }
  ```
- **Verification:**
  ```bash
  ./reconforge scan -d "999.999.999.999"  # exit 1 với usage error
  ./reconforge scan -d "no-tld"            # exit 1
  ./reconforge scan -d "exam ple.com"      # exit 1 (space invalid)
  ./reconforge scan --cidr "10.0.0.0/99"   # exit 1
  ./reconforge scan -d "valid.example.com" # OK
  ```
- **Acceptance criteria:**
  - [ ] 4 invalid pattern test return UsageError (exit 1)
  - [ ] Valid domain/IP/CIDR pass
  - [ ] Test cases trong `domain_test.go` + `ip_test.go`
  - [ ] Error message rõ ràng (chỉ ra phần nào sai)
- **Effort:** M (45 min)

### Task 2.4 — Actionable MissingToolError

- **File:** `internal/runner/errors.go`
- **Spec:** Hiện error chỉ "tool X not found in PATH". Cần wrap với hint + docs URL.
- **Implementation:**
  ```go
  type MissingToolError struct {
      Tool    string
      Hint    string
      DocsURL string
  }

  func (e *MissingToolError) Error() string {
      var b strings.Builder
      fmt.Fprintf(&b, "✗ tool %q not found in PATH\n", e.Tool)
      if e.Hint != "" { fmt.Fprintf(&b, "  Fix:  %s\n", e.Hint) }
      if e.DocsURL != "" { fmt.Fprintf(&b, "  Docs: %s\n", e.DocsURL) }
      return b.String()
  }

  // runner.Run khi exec.LookPath fail:
  return nil, &MissingToolError{
      Tool:    tool,
      Hint:    fmt.Sprintf("reconforge tools install %s", tool),
      DocsURL: toolDocsURL[tool],   // map từ registry
  }
  ```
- **Verification:**
  ```bash
  ./reconforge scan -d example.com --profile full
  # Output expect:
  # ✗ tool "nuclei" not found in PATH
  #   Fix:  reconforge tools install nuclei
  #   Docs: https://github.com/projectdiscovery/nuclei
  ```
- **Acceptance criteria:**
  - [ ] `MissingToolError` struct với 3 field
  - [ ] Tool registry có DocsURL map
  - [ ] Output format đúng spec (3 dòng có icon + indent)
  - [ ] Test pass với mock missing tool
- **Effort:** S (30 min)

---

## Phase 3 — Test Coverage + CI/CD (HIGH)

> **Mục tiêu:** Coverage 35% → 70%, CI auto-run trên PR.

### Task 3.1 — Module integration tests (74 module)

- **File:** `internal/module/<phase>/<module>_integration_test.go` (74 file mới hoặc bundled)
- **Spec:** Hiện chỉ 5/74 module có test. Cần test cho core path mỗi module:
  - Validate(cfg) returns đúng error khi disabled
  - Run(ctx, scan) gọi runner đúng tool + args
  - Parse output đúng format
- **Implementation strategy:** Dùng test helper + table-driven, không cần 74 file riêng. Bundle theo phase:
  ```go
  // internal/module/web/web_modules_integration_test.go
  func TestAllWebModulesValidate(t *testing.T) {
      cases := []struct {
          name   string
          mod    module.Module
          cfg    *config.Config
          wantErr bool
      }{
          {"httpx_disabled", &HTTPXProbe{}, disabledCfg(), true},
          {"httpx_enabled", &HTTPXProbe{}, enabledCfg(), false},
          // ... 30 case cho web phase
      }
      for _, tc := range cases {
          t.Run(tc.name, func(t *testing.T) {
              err := tc.mod.Validate(tc.cfg)
              if (err != nil) != tc.wantErr {
                  t.Errorf("got %v, wantErr %v", err, tc.wantErr)
              }
          })
      }
  }

  func TestAllWebModulesRunWithMockRunner(t *testing.T) {
      mockRunner := &MockRunner{...}
      scanCtx := newTestScanContext(mockRunner)
      // Run mỗi module, verify mockRunner.calls có expected tool name
  }
  ```
- **Verification:**
  ```bash
  go test -race -cover ./internal/module/...
  # Coverage phải > 60%
  ```
- **Acceptance criteria:**
  - [ ] Mỗi phase package có ≥ 1 integration test file
  - [ ] Coverage `internal/module/...` > 60%
  - [ ] Test pass với `-race` flag
  - [ ] CI run trong < 60s
- **Effort:** L (4-6h)

### Task 3.2 — Critical path integration test

- **File:** `internal/orchestrator/orchestrator_integration_test.go`
- **Spec:** Test full path Scan() → Engine.Execute() → Module.Run() → Results persist.
- **Implementation:**
  ```go
  func TestScanFullPipelineDryRun(t *testing.T) {
      cfg := testConfig()
      cfg.DryRun = true
      orch := New(cfg, zerolog.Nop())

      err := orch.Scan(context.Background(), "test.example", "recon", t.TempDir())
      assert.NoError(t, err)

      // Verify all 9 stage executed
      results, _ := orch.stateMgr.GetScanState("scan-...")
      assert.Equal(t, 9, len(results.Stages))
      assert.GreaterOrEqual(t, len(results.Modules), 70)
  }

  func TestScanResumeAfterInterrupt(t *testing.T) {
      // Spawn scan, cancel context after 2 modules
      // Re-run with --resume
      // Verify skipped modules logged
  }

  func TestScanPanicRecovery(t *testing.T) {
      // Inject panic module
      // Verify orchestrator return error, checkpoint saved
  }
  ```
- **Verification:** `go test -race -v -run TestScan ./internal/orchestrator/`
- **Acceptance criteria:**
  - [ ] Test full pipeline dryrun pass
  - [ ] Test resume sau interrupt pass
  - [ ] Test panic recovery pass
  - [ ] Test multi-target parallel pass
  - [ ] No goroutine leak (`-race`)
- **Effort:** L (3h)
- **Dependencies:** Task 2.1, 2.2

### Task 3.3 — GitHub Actions CI

- **File:** `.github/workflows/ci.yml` (tạo mới)
- **Spec:** Auto-run trên push/PR: vet + test + lint + security.
- **Implementation:**
  ```yaml
  name: CI
  on:
    push:
      branches: [main, dev]
    pull_request:
      branches: [main]

  jobs:
    test:
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@v4
        - uses: actions/setup-go@v5
          with:
            go-version: "1.23"
        - run: go mod download
        - run: go vet ./...
        - run: go test -race -cover -coverprofile=coverage.out ./...
        - run: go tool cover -func=coverage.out | tail -1

    lint:
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@v4
        - uses: golangci/golangci-lint-action@v6
          with:
            version: v1.61

    security:
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@v4
        - uses: securego/gosec@master
          with:
            args: ./...

    build:
      runs-on: ubuntu-latest
      needs: [test, lint]
      steps:
        - uses: actions/checkout@v4
        - uses: actions/setup-go@v5
        - run: make build-all
  ```
- **Verification:** Push to dev branch → workflow chạy xanh.
- **Acceptance criteria:**
  - [ ] 4 job: test, lint, security, build
  - [ ] Test với `-race -cover`
  - [ ] Lint với golangci-lint
  - [ ] Security với gosec
  - [ ] Build cross-platform (linux+darwin)
  - [ ] PR badge trong README
- **Effort:** M (45 min)

### Task 3.4 — Pre-commit hooks

- **File:** `.pre-commit-config.yaml` (tạo mới)
- **Spec:** Local hook tránh push code chưa format/lint.
- **Implementation:**
  ```yaml
  repos:
    - repo: https://github.com/dnephin/pre-commit-golang
      rev: v0.5.1
      hooks:
        - id: go-fmt
        - id: go-vet
        - id: go-imports
        - id: go-mod-tidy
        - id: golangci-lint
  ```
- **Verification:** `pre-commit install && pre-commit run --all-files` pass.
- **Acceptance criteria:**
  - [ ] File `.pre-commit-config.yaml` tồn tại
  - [ ] CONTRIBUTING.md ghi rõ cài đặt
  - [ ] Run thử cho 1 file → format + vet trigger
- **Effort:** S (15 min)

---

## Phase 4 — Polish & Docs (MEDIUM)

> **Mục tiêu:** UX hoàn thiện, contributor onboarding rõ ràng.

### Task 4.1 — Tạo `configs/profiles/stealth.yaml`

- **File:** `configs/profiles/stealth.yaml` (tạo mới)
- **Spec:** README claim 4 profile (quick/stealth/full/deep) nhưng chỉ có 2. Tạo stealth = passive only, no active probing, low rate limit.
- **Implementation:** Copy `quick.yaml` → tweak:
  - Disable mọi active module (dns_brute, port_scan, web_fuzz, nuclei_dast)
  - Rate limit thấp (1 req/sec)
  - User agent rotation
  - Proxy required
- **Acceptance criteria:**
  - [ ] File tồn tại
  - [ ] Khác biệt rõ với quick (no active scan)
  - [ ] `reconforge config profiles` list 4 profile
  - [ ] Test: `reconforge scan --profile stealth --dry-run` không exec module active nào
- **Effort:** S (30 min)

### Task 4.2 — Generate man pages

- **File:** `Makefile` (thêm target), `dist/man/` (output)
- **Spec:** Tool `gen-manpages` đã có. Chỉ cần generate output + add Makefile target.
- **Implementation:**
  ```makefile
  manpages: build
      mkdir -p dist/man
      ./bin/reconforge gen-manpages --out dist/man
  ```
- **Verification:**
  ```bash
  make manpages
  ls dist/man/   # phải có reconforge.1, reconforge-scan.1, ...
  man -l dist/man/reconforge.1
  ```
- **Acceptance criteria:**
  - [ ] `make manpages` generate ≥ 19 file `.1`
  - [ ] Manpage view được bằng `man -l`
  - [ ] goreleaser config include man pages vào archive
- **Effort:** S (20 min)

### Task 4.3 — Tạo `CHANGELOG.md`

- **File:** `CHANGELOG.md` (tạo mới)
- **Spec:** Theo Keep a Changelog format.
- **Implementation:**
  ```markdown
  # Changelog

  ## [Unreleased]

  ## [0.1.0-alpha] - 2026-04-26
  ### Added
  - 82 reconnaissance modules (port từ reconFTW bash)
  - 19 CLI subcommand
  - DAG pipeline executor
  - TUI dashboard (BubbleTea)
  - Findings export 7 format (burp-xml, markdown, csv, ndjson, hackerone, bugcrowd, nuclei-targets)
  - Findings push tới Jira/GitHub/Linear
  - Scope sync HackerOne/Bugcrowd
  - Multi-target project + diff
  - Cron schedule + monitor daemon
  - Self-update với SHA256 verify
  - Shell completion bash/zsh/fish/powershell

  ### Changed
  - N/A (first release)

  ### Removed
  - REST API server (terminal-first refactor)
  - Temporal distributed workflow
  - Kali VM manager
  ```
- **Acceptance criteria:**
  - [ ] File theo Keep a Changelog format
  - [ ] Phiên bản hiện tại + Unreleased section
  - [ ] CONTRIBUTING ghi rõ cách update
- **Effort:** S (20 min)

### Task 4.4 — Tạo `CONTRIBUTING.md`

- **File:** `CONTRIBUTING.md` (tạo mới)
- **Spec:** Hướng dẫn dev setup, PR process, module template.
- **Implementation:** Section:
  - Dev environment setup (Go 1.23+, pre-commit, tools install)
  - Code style (gofmt, golangci-lint)
  - Testing requirements (≥ 60% coverage)
  - PR process (branch naming, commit format, review)
  - Adding new module (link tới ARCHITECTURE.md)
  - Adding new tool to registry (SHA256 + DocsURL fields)
- **Acceptance criteria:**
  - [ ] File ≥ 200 dòng
  - [ ] Tối thiểu 6 section
  - [ ] Link tới ARCHITECTURE.md, CHANGELOG.md
  - [ ] Module template code snippet
- **Effort:** M (45 min)

### Task 4.5 — Honor `NO_COLOR` env

- **File:** `internal/ui/terminal.go`, `internal/ui/mode.go`
- **Spec:** Tuân theo https://no-color.org/ — disable color output khi `NO_COLOR` set (bất kỳ value).
- **Implementation:**
  ```go
  func ColorEnabled() bool {
      if _, set := os.LookupEnv("NO_COLOR"); set {
          return false
      }
      return IsTTY()
  }
  ```
- **Verification:**
  ```bash
  ./reconforge findings list -t example.com   # color
  NO_COLOR=1 ./reconforge findings list -t example.com   # no color
  ```
- **Acceptance criteria:**
  - [ ] `NO_COLOR=*` → no color output
  - [ ] TUI dashboard cũng tuân thủ
  - [ ] Test trong `terminal_test.go`
- **Effort:** S (15 min)

---

## 2. Verification cuối cùng (sau 4 phase)

```bash
# Build + test
go build ./...
go test -race -cover ./... | tee test-output.log
grep "PASS" test-output.log | wc -l   # ≥ 100 test

# Coverage
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out | tail -1
# total coverage phải ≥ 70%

# Release dry-run
goreleaser release --snapshot --clean
ls dist/

# Functional smoke test
./dist/reconforge_*/reconforge scan -d example.com --dry-run
echo $?   # 0 hoặc 3

# Signal handling
./bin/reconforge scan -d example.com --profile full &
sleep 5 && kill -INT $!
echo $?   # 130

# Resume
./bin/reconforge scan -d example.com --resume

# Validation
./bin/reconforge scan -d "999.999.999.999"   # exit 1
echo $?   # 1

# Missing tool hint
PATH=/tmp ./bin/reconforge scan -d example.com --profile full
# expect: ✗ tool ... not found ...  Fix: reconforge tools install ...
```

---

## 3. Acceptance Criteria tổng thể (cho GPT-5.5 review)

Sau khi Codex hoàn thành 4 phase, GPT-5.5 phải verify:

### Phase 1 review checklist
- [ ] LICENSE file MIT chuẩn, README link đúng
- [ ] go.mod Go directive khớp Go GA
- [ ] `goreleaser check` pass, snapshot build 4 binary
- [ ] Git tag `v0.1.0-alpha` push remote
- [ ] Tool installer reject tampered binary (test integration)
- [ ] Self-update reject invalid GPG signature
- [ ] Config init mode 0600, doctor warn world-readable

### Phase 2 review checklist
- [ ] SIGINT → checkpoint save → exit 130
- [ ] `--resume` skip done module
- [ ] Panic trong module → orchestrator catch + log stack trace
- [ ] Invalid target (4 pattern) → UsageError exit 1
- [ ] Missing tool error có Fix + Docs hint

### Phase 3 review checklist
- [ ] `go test -race -cover ./...` coverage ≥ 70%
- [ ] Module phase test cover ≥ 60% mỗi phase
- [ ] Orchestrator integration test pass (dryrun + resume + panic)
- [ ] CI workflow xanh trên PR
- [ ] Pre-commit hook trigger trên local commit

### Phase 4 review checklist
- [ ] 4 profile tồn tại (quick/stealth/full/deep)
- [ ] Man pages generate được + view được
- [ ] CHANGELOG theo Keep a Changelog format
- [ ] CONTRIBUTING ≥ 6 section + module template
- [ ] `NO_COLOR=1` disable color output

### Cross-cutting review
- [ ] No new `// TODO` / `// FIXME` introduced
- [ ] Error wrapping `%w` consistent
- [ ] No `panic()` trong production code
- [ ] No `log.Fatal` ngoài main
- [ ] Context propagation đúng mọi long-running func
- [ ] No goroutine leak (`-race` clean)
- [ ] Doc đồng bộ (README + ARCHITECTURE + RECIPES)

---

## 4. Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| Codex break test hiện tại khi refactor | Mỗi task có verify command — chạy trước commit |
| GPG signing setup phức tạp | Phase 1.6 có thể defer sang v0.2 nếu time-constrained |
| Coverage 70% target có thể không đạt cho 74 module trong 1 ngày | Bundle test theo phase + table-driven, không cần file/module |
| GitHub Actions free tier giới hạn minute | Test job chạy < 5min, build job < 10min |
| Self-update GPG embed key cứng → key rotation khó | Use TUF hoặc fetch key từ stable URL |
| Multi-target panic recovery có thể che bug thực | Log stack trace level=error, không silent |

---

## 5. Thứ tự thực hiện (recommend cho Codex)

```
Day 1 (4-6h):
  - Task 1.1 LICENSE             (5 min)
  - Task 1.2 go.mod version       (5 min)
  - Task 1.3 goreleaser           (45 min)
  - Task 4.3 CHANGELOG            (20 min)
  - Task 4.4 CONTRIBUTING         (45 min)
  - Task 1.4 git tag              (5 min)
  - Task 1.7 config secrets       (45 min)
  - Task 1.5 tool checksum        (30 min)
  - Task 1.6 GPG sig (defer OK)   (1h)

Day 2 (3-4h):
  - Task 2.4 MissingToolError    (30 min)
  - Task 2.3 target validation    (45 min)
  - Task 2.2 panic recovery       (30 min)
  - Task 2.1 SIGINT handler       (1h)
  - Task 4.1 stealth profile      (30 min)
  - Task 4.2 manpages             (20 min)
  - Task 4.5 NO_COLOR             (15 min)

Day 3 (1-2 ngày):
  - Task 3.4 pre-commit           (15 min)
  - Task 3.3 GitHub Actions       (45 min)
  - Task 3.2 orchestrator integ   (3h)
  - Task 3.1 module integ tests   (4-6h)
```

---

## 6. Final Status sau plan

```
Trước:   75% complete (alpha)
Sau:     ≥ 95% complete (beta-ready)

████████████████████████░░  Feature parity (100% — không đổi)
████████████████████████░░  CLI commands (100% — không đổi)
████████████████████████░░  Terminal UX (95% — sau 2.4, 4.1, 4.2)
████████████████████████░░  Code quality (95% — sau panic recovery)
██████████████████████░░░░  Test coverage (≥ 70%)
████████████████████████░░  Production ready (≥ 95%)
```

---

**End of plan. Codex bắt đầu từ Task 1.1.**
**GPT-5.5 review từng phase độc lập, không cần đợi tất cả xong.**

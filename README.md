# ReconForge

> Framework reconnaissance terminal-first — Go port của [reconFTW](https://github.com/six2dez/reconftw).
> Single binary. Single user. Single machine. Không server, không VM.

[![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Status](https://img.shields.io/badge/status-alpha-orange)]()

---

## Cài đặt

```bash
# Build từ source (cần Go 1.23+)
git clone https://github.com/duongpahm/reconforge.git
cd reconforge/reconforge
go build -ldflags="-s -w" -o reconforge ./cmd/reconforge
```

## 60 giây đầu tiên

```bash
./reconforge init --yes              # Bootstrap config + DB
./reconforge doctor                  # Check môi trường
./reconforge tools install all       # Cài 9 tool external
./reconforge scan -d example.com --dry-run    # Test pipeline
./reconforge scan -d example.com --profile quick
./reconforge findings list -t example.com --severity high,critical
```

Output lưu tại `./Recon/<target>/` gồm: raw output theo phase, `state.db` (SQLite), `report.{json,md,html}`.

## License

ReconForge is released under the [MIT License](LICENSE).

## Release signing key

- Fingerprint: `4C10 5CE2 18BD E48C 2267 0A2B B314 7C45 1DC4 8DAF`
- Public key: [`cmd/reconforge/release-public-key.asc`](cmd/reconforge/release-public-key.asc)

---

## Tính năng

- **82 module** chia 4 phase: OSINT → Subdomain → Web → Vuln
- **DAG pipeline** với dependency tường minh + parallel execution
- **TUI dashboard** auto-detect TTY, fallback ndjson khi pipe
- **Pipe-friendly** native: `findings list | jq | httpx`
- **Resume** sau crash từ checkpoint
- **Proxy** universal cho mọi tool subprocess (Burp/ZAP)
- **19 subcommand**: scan, findings, project, scope, schedule, monitor, notify, doctor, ...
- **Stable exit codes** cho CI/CD
- **Self-update** qua GitHub Releases (SHA256 verified)

---

## CLI Reference

```
reconforge scan         Chạy scan
reconforge findings     Query / triage / replay / export findings
reconforge project      Quản lý multi-target engagement
reconforge scope        Validate / sync scope (HackerOne/Bugcrowd)
reconforge diff         So sánh 2 lần scan
reconforge monitor      Continuous monitoring
reconforge schedule     Cron-based scheduled scans
reconforge notify       Notification rules (Discord/Slack/Telegram)
reconforge report       Generate report (hackerone/bugcrowd/executive)
reconforge tools        Install / list / path tool external
reconforge doctor       Health check
reconforge cache        Quản lý cache
reconforge init         Bootstrap config + DB
reconforge config       Show / validate / list profile
reconforge tail         Follow scan progress realtime
reconforge completion   Shell completion (bash/zsh/fish)
reconforge self-update  Update từ GitHub Releases
reconforge version      Print version
```

### Scan flags

| Flag | Mô tả |
|------|-------|
| `-d, --domain` | Target domain |
| `-l, --list` | File chứa list target |
| `--cidr` | Target CIDR |
| `-m, --mode` | `recon` (default), `passive`, `osint`, `web` |
| `-p, --profile` | `quick`, `stealth`, `full`, `deep` |
| `--parallel N` | Scan nhiều target song song |
| `--proxy URL` | HTTP(S) proxy cho mọi tool subprocess |
| `--dry-run` | Simulate không exec tool thật |
| `--skip-missing-tools` | Skip module thiếu tool |
| `--resume` | Resume scan đã interrupt |
| `--tail` | Follow progress realtime |
| `--inscope` | Path tới `.scope` file |

---

## Module Coverage

**82 module** đăng ký:

| Phase | Số module | Examples |
|-------|-----------|----------|
| OSINT | 15 | `email_harvest`, `google_dorks`, `github_leaks`, `cloud_enum`, `mail_hygiene`, ... |
| Subdomain | 22 | `subfinder`, `crt_sh`, `dns_brute`, `permutations`, `takeover`, ... |
| Web | 30 | `httpx_probe`, `screenshots`, `crawler`, `nuclei_check`, `web_fuzz`, `cms_scanner`, ... |
| Vuln | 15 | `nuclei`, `xss_scan`, `sqli_scan`, `ssrf_scan`, `nuclei_dast`, `bypass_4xx`, `lfi_check`, ... |

Đầy đủ danh sách module trong [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
Test regression: `internal/orchestrator/registry_coverage_test.go` đảm bảo mọi module đăng ký phải có ≥ 1 stage trong pipeline.

---

## Scan Modes

| Mode | Pipeline |
|------|----------|
| `recon` | Full: OSINT → Subdomain (4 stage) → Web (3 stage) → Vuln |
| `passive` | OSINT + passive subdomain |
| `osint` | OSINT only |
| `web` | Web + Vuln (assume subdomains đã có) |

## Profiles

YAML profile tại `configs/profiles/`. Tự định nghĩa bằng cách copy `full.yaml` và disable module không cần.

| Profile | Use case |
|---------|----------|
| `quick` | Fast triage |
| `full` | Complete recon |
| `stealth` | OPSEC-safe |
| `deep` | Deep mode + extra modules |

---

## Workflow Examples

### Daily bug bounty hunt

```bash
reconforge project create acme --scope ./acme.scope
reconforge project add-target acme acme.com app.acme.com api.acme.com
reconforge schedule add acme --cron "0 2 * * *" --profile full

# Sáng dậy
reconforge project findings acme --since 24h --severity high,critical
```

### Burp manual hunt

```bash
# Burp listen :8080
reconforge scan -d target.com --profile web --proxy http://127.0.0.1:8080
reconforge findings replay <id> --proxy http://127.0.0.1:8080
```

### Pipe to other tools

```bash
# Re-probe sub findings với httpx
reconforge findings list -t acme --type subdomain --format plain | httpx -status-code

# Severity counting
reconforge findings list -t acme --format ndjson | \
  jq -s 'group_by(.severity) | map({sev: .[0].severity, count: length})'
```

### CI/CD gate

```bash
reconforge scan -d acme.com --profile quick
case $? in
  0) echo "Clean" ;;
  3) echo "Critical found" && exit 1 ;;
  *) echo "Scan error" && exit 1 ;;
esac
```

Đầy đủ recipe (13 workflow) trong [`docs/RECIPES.md`](docs/RECIPES.md).

---

## Exit Codes

| Code | Ý nghĩa |
|------|---------|
| 0 | OK |
| 1 | Usage error |
| 2 | Scan failed |
| 3 | Critical/high finding detected |
| 4 | Required tool missing |
| 5 | Config invalid |
| 6 | Scope invalid |
| 130 | Interrupted (SIGINT) |

---

## Development

```bash
go build ./...                          # Build
go test -race ./...                     # Test với race detector
go test -cover ./...                    # Coverage
gofmt -w . && go vet ./...              # Format + vet
```

### Thêm module mới

1. Tạo `internal/module/<phase>/<name>.go` implement `Module` interface
2. Đăng ký vào `internal/module/<phase>/register.go`
3. **Wire vào pipeline** tại `internal/orchestrator/orchestrator.go`
4. Thêm config field vào `internal/config/config.go` (nếu cần)
5. `go build ./... && go test ./...`

> ⚠️ Bỏ qua step 3 → `TestAllRegisteredModulesAreWired` sẽ fail. Chi tiết: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## Tài liệu

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — Internal architecture, layer responsibilities, data flow
- [`docs/RECIPES.md`](docs/RECIPES.md) — 13 workflow recipes
- [`docs/PIPE_RECIPES.md`](docs/PIPE_RECIPES.md) — Pipe-friendly snippets
- [`AUDIT_FIX_PLAN.md`](AUDIT_FIX_PLAN.md) — Audit fix plan (đã hoàn thành P0/P1/P2)
- [`TERMINAL_OPTIMIZATION_PLAN.md`](TERMINAL_OPTIMIZATION_PLAN.md) — Roadmap

---

## Legal

Tool này **chỉ dùng cho authorized security testing**: pentest, bug bounty trong scope, CTF, defensive research trên asset bạn sở hữu. Scan target không có quyền là **bất hợp pháp** ở phần lớn quốc gia.

ReconForge không cung cấp exploitation payload riêng — chỉ orchestrate detection patterns trong các tool công khai (nuclei, dalfox, sqlmap, ...). Đây là platform **reconnaissance + discovery**.

---

## Credits

- [reconFTW](https://github.com/six2dez/reconftw) by [@six2dez](https://github.com/six2dez) — methodology + tool selection.
- ProjectDiscovery suite, dalfox, sqlmap, katana, TInjA, CMSeeK và mọi upstream tool.
- Cộng đồng offensive security.

## License

[MIT](LICENSE)

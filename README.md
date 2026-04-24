# ReconForge

> **All-in-One Offensive Reconnaissance Platform — rebuilt in Go.**
> A complete Go port of [reconFTW](https://github.com/six2dez/reconftw) with a module-based architecture, type-safe config, concurrent pipeline execution, and a REST/TUI/CLI triple interface.

[![Go Version](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Status](https://img.shields.io/badge/status-alpha-orange)]()

---

## Why ReconForge?

reconFTW is a best-in-class bash reconnaissance framework, but bash hits real ceilings: no type safety, no structured concurrency, no testing, no first-class API surface, brittle error handling. ReconForge keeps the tool ecosystem and methodology of reconFTW and wraps them in a proper engineered runtime:

- **82 reconnaissance modules** organized into 4 phases (OSINT → Subdomain → Web → Vuln)
- **DAG-based pipeline** with explicit dependencies and parallel execution
- **Type-safe Viper config** with YAML profiles and runtime validation
- **Concurrent runner** with rate limiting, adaptive throttling, and timeout control
- **Three interfaces:** CLI (cobra), TUI (BubbleTea), REST API + WebSocket (gin)
- **Temporal workflow support** for distributed long-running scans
- **Structured logging** (zerolog) + queryable SQLite result store (GORM)
- **Scan profiles:** `quick`, `full`, `passive`, `osint`, `web`, `recon`
- **~20k LOC of Go**, 27 test files, 18/18 test packages passing

---

## Quick Start

### Prerequisites

- **Go 1.25+**
- **External recon tools** (installed via `reconforge tools install` or manually): `subfinder`, `httpx`, `nuclei`, `katana`, `dalfox`, `sqlmap`, `waymore`, `naabu`, `nmap`, `crlfuzz`, `TInjA`, `commix`, `nomore403`, `smugglex`, `ffuf`, `CMSeeK`, `VhostFinder`, `asnmap`, `dnsx`, `tlsx`, `gitdorks_go`, `whois`, `porch-pirate`, `spoofy`, `favirecon`, `brutespray`, `Web-Cache-Vulnerability-Scanner`, `toxicache`, `cdncheck`, `gqlspection`, `enumerepo`, `gitleaks`, `trufflehog`, `metagoofil`, `misconfig-mapper`, `subjs`, `mantra`, `roboxtractor`, `grpcurl`, `gotator`, `regulator`, `hakrevdns`, `analyticsrelationships`, `unfurl`, `anew`, `qsreplace`, `gf`, `shortscan`, `urlfinder`
- **System packages:** `dig`, `curl`, `git`

### Install

```bash
git clone https://github.com/duongpahm/reconforge.git
cd reconforge
go mod download
go build -o bin/reconforge ./cmd/reconforge
```

### First scan

```bash
# Quick scan on a domain
./bin/reconforge scan -t example.com --profile quick

# Full scan with deep mode
./bin/reconforge scan -t example.com --profile full --deep

# Headless (no TUI)
./bin/reconforge scan -t example.com --profile full --no-tui --log-level info
```

Output lands in `./output/example.com/` with this structure:

```
output/example.com/
├── osint/              # WHOIS, emails, API leaks, spoof check...
├── subdomains/         # Subdomain enumeration results
├── hosts/              # IPs, ports, service fingerprints
├── webs/               # HTTPX probes, screenshots, crawled URLs, favicons
├── js/                 # JS analysis, secret extraction
├── fuzzing/            # Directory/vhost fuzzing
├── gf/                 # GF pattern-filtered URLs (xss.txt, sqli.txt, …)
├── nuclei_output/      # Nuclei JSON per severity level
├── vulns/              # Vulnerability findings by category
├── cms/                # CMSeeK results
└── report/             # Final JSON/HTML/PDF reports
```

---

## CLI Overview

```
reconforge scan       Run reconnaissance scan on a target
reconforge server     Start the REST API + Web Dashboard
reconforge worker     Start a Temporal worker for distributed scans
reconforge tools      Manage security tools
  ├── check             Health check all required tools
  └── install           Install missing tools
reconforge config     Manage configuration
  ├── show              Show current configuration
  ├── validate          Validate configuration file
  └── profiles          List available scan profiles
reconforge report     Generate reports from scan results
reconforge vm         Manage a Kali Linux VM (Tart/QEMU)
  ├── setup / status / start / stop / ssh / destroy
reconforge version    Print version information
```

---

## Module Coverage

**82 modules registered**, matching and exceeding the original bash framework.

| Phase | Modules | Coverage |
|-------|---------|----------|
| **OSINT** | 15 | `email_harvest`, `google_dorks`, `github_dorks`, `github_leaks`, `github_repos`, `github_actions_audit`, `cloud_enum`, `spf_dmarc`, `domain_info`, `api_leaks`, `spoof_check`, `ip_info`, `third_parties`, `metadata`, `mail_hygiene` |
| **Subdomain** | 22 | Passive (`subfinder`, `crtsh`, `github_subdomains`), Active (`dns_brute`, `permutation`, `resolver`, `recursive`), TLS/DNS (`tls_grab`, `zone_transfer`, `srv_enum`, `noerror`, `ns_delegation`), Discovery (`asn_enum`, `source_scraping`, `analytics`, `regex_permut`, `ia_permut`, `ptr_cidrs`, `geo_info`), Post-processing (`wildcard_filter`, `takeover`, `s3_buckets`) |
| **Web** | 30 | Probing (`httpx_probe`, `screenshots`, `crawler`, `favirecon_tech`), Analysis (`js_analysis`, `sub_js_extract`, `js_checks`, `waf_detector`, `param_discovery`, `cdn_provider`, `service_fingerprint`), Scanning (`port_scan`, `virtual_hosts`, `web_fuzz`, `nuclei_check`, `cms_scanner`, `iis_shortname`, `tls_ip_pivots`, `well_known_pivots`), Crawling (`url_checks`, `url_gf`, `url_ext`, `broken_links`, `sub_js_extract`), Specialized (`graphql`, `grpc_reflection`, `websocket_checks`, `llm_probe`, `wordlist_gen`, `wordlist_gen_roboxtractor`, `password_dict`) |
| **Vuln** | 15 | `nuclei`, `nuclei_dast`, `dalfox_xss`, `sqlmap`, `ssrf`, `ssl_audit`, `crlf`, `lfi`, `ssti`, `command_injection`, `bypass_4xx`, `http_smuggling`, `webcache`, `fuzzparams`, `spraying` |

See [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) for architecture details and contribution guide.

---

## Scan Profiles

Profiles live in [`configs/profiles/`](configs/profiles/). Current profiles:

| Profile | Use case | Modules enabled |
|---------|----------|-----------------|
| **quick** | Fast triage (<10 min on small targets) | passive subdomain enum + httpx probe + nuclei (medium+) |
| **full** | Complete recon (hours) | All modules — OSINT, active subdomain, web, vuln, DAST |
| **passive** | OPSEC-safe | OSINT + passive subdomain enum only, no active probing |
| **osint** | OSINT only | Email harvest, github dorks, domain info, API leaks |
| **web** | Post-subdomain web-focused | HTTPX + crawl + nuclei + DAST + fuzz |
| **recon** | Full pipeline | Identical to `full` |

Define your own profile by copying `configs/profiles/full.yaml` and disabling modules you don't need.

---

## REST API & Web Dashboard

```bash
reconforge server --addr :8080
```

Endpoints:
- `POST /api/scans` — start a scan
- `GET /api/scans/:id` — get scan status
- `GET /api/scans/:id/findings` — list findings
- `GET /api/scans/:id/live` — WebSocket stream of real-time progress
- `GET /api/modules` — list all registered modules
- `GET /api/profiles` — list available profiles

---

## Architecture

```
cmd/reconforge/              # CLI entrypoint (cobra)
internal/
├── api/                     # REST API + WebSocket
├── cache/                   # Resolver & wordlist caching
├── config/                  # Viper-based typed config
├── engine/                  # Pipeline DAG, phases, stages
├── models/                  # GORM models (SQLite)
├── module/
│   ├── osint/               (15 modules)
│   ├── subdomain/           (22 modules)
│   ├── web/                 (30 modules)
│   └── vuln/                (15 modules)
├── notify/                  # Discord/Slack/Telegram
├── orchestrator/            # Scan orchestration
├── output/                  # JSON/YAML/Markdown writers
├── ratelimit/               # Adaptive rate limiting
├── report/                  # Report generation
├── runner/                  # External tool executor
├── temporal/                # Temporal workflows
├── ui/                      # BubbleTea TUI
└── vm/                      # Kali VM manager
pkg/
├── scope/                   # In-scope validation
├── tool/                    # Tool wrappers + installer
└── types/                   # Shared types (Domain, IP, URL, Finding)
test/e2e/                    # End-to-end scan tests
```

### Module Interface

Every module conforms to a single contract — no special cases:

```go
type Module interface {
    Name() string
    Description() string
    Phase() engine.Phase
    Dependencies() []string
    RequiredTools() []string
    Validate(cfg *config.Config) error
    Run(ctx context.Context, scan *module.ScanContext) error
}
```

Modules are registered once in `internal/module/<phase>/register.go` and the orchestrator handles scheduling, parallelization, dependency resolution, and result aggregation.

---

## Development

```bash
# Build
go build ./...

# Run all tests
go test ./...

# Run with race detector
go test -race ./...

# Run a specific package
go test ./internal/module/web/... -v

# Format & vet
gofmt -w .
go vet ./...
```

### Adding a new module

1. Create `internal/module/<phase>/<name>.go` implementing the `Module` interface
2. Register it in `internal/module/<phase>/register.go`
3. Add config fields to `internal/config/config.go` if needed
4. Update test counts in `<phase>_test.go` and `orchestrator_test.go`
5. Run `go build ./... && go test ./...`

Full guide and templates in [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md).

---

## Legal & Ethics

This tool is for **authorized security testing only** — pentests, bug bounty programs you have explicit scope for, CTF challenges, and defensive research on assets you own. Scanning targets without permission is illegal in most jurisdictions.

ReconForge does not provide exploitation payloads beyond standard detection patterns already shipped in public tools (nuclei, dalfox, sqlmap, etc.). It is a reconnaissance and discovery platform.

---

## Credits

- **Original [reconFTW](https://github.com/six2dez/reconftw)** by [@six2dez](https://github.com/six2dez) — the methodology, tool selection, and years of recon tradecraft that made this port possible.
- The authors of every upstream tool ReconForge orchestrates (ProjectDiscovery suite, dalfox, sqlmap, katana, TInjA, CMSeeK, …).
- Built for and by the offensive security community.

---

## License

MIT — see [LICENSE](LICENSE).

---

## Roadmap

- [ ] Real-tool E2E fixture tests (mock recorded tool output)
- [ ] Scan diffing (compare two scans, emit deltas)
- [ ] Continuous monitoring mode (cron-triggered rescans with alerting)
- [ ] Distributed mode via Temporal + axiom-compatible backend
- [ ] Web Dashboard (React SPA)
- [ ] Plugin system for user-defined modules without recompile
- [ ] Scope-aware reporting (severity aggregation per asset class)

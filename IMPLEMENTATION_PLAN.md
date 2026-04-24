# reconforge Implementation Plan

> **Mục tiêu:** Port toàn bộ reconFTW bash framework (v4.1) sang Go với kiến trúc module hoá, type-safe, concurrent.
> **Audience:** Codex / AI coding agent
> **Ngày tạo:** 2026-04-23
> **Codebase hiện tại:** 15,705 dòng Go, 57 modules đã đăng ký, build sạch, 15/15 test packages pass.

---

## 1. Tình trạng hiện tại (Current State)

### 1.1. Kiến trúc đã có

```
reconforge/
├── cmd/reconforge/main.go          # CLI entrypoint (cobra)
├── internal/
│   ├── api/                        # REST API (gin) + WebSocket stub
│   ├── cache/                      # Cache resolvers, wordlists
│   ├── config/                     # Viper-based config
│   ├── engine/                     # Pipeline DAG, phases, stages
│   ├── models/                     # GORM models (SQLite)
│   ├── module/
│   │   ├── osint/      (9 modules)
│   │   ├── subdomain/  (18 modules)
│   │   ├── web/        (15 modules)
│   │   └── vuln/       (15 modules) ← 100% coverage
│   ├── notify/                     # Discord/Slack notifications
│   ├── orchestrator/               # Scan orchestration
│   ├── output/                     # Writers JSON/YAML/MD
│   ├── ratelimit/                  # Adaptive rate limiting
│   ├── report/                     # Report generation
│   ├── runner/                     # External tool executor
│   ├── temporal/                   # Temporal workflows
│   ├── ui/                         # BubbleTea TUI
│   └── vm/                         # VM manager (distributed)
├── pkg/
│   ├── scope/                      # In-scope validation
│   ├── tool/                       # Tool wrappers
│   └── types/                      # Shared types
└── go.mod                          # Go 1.25, key deps: cobra, viper, gin, gorm, zerolog, temporal SDK
```

### 1.2. Module API contract

Mọi module phải implement interface `module.Module`:

```go
type Module interface {
    Name() string                                        // "http_smuggling"
    Description() string                                 // Human-readable desc
    Phase() engine.Phase                                 // PhaseOSINT/Subdomain/Web/Vuln
    Dependencies() []string                              // Module names it depends on
    RequiredTools() []string                             // CLI tools needed
    Validate(cfg *config.Config) error                   // Pre-flight check
    Run(ctx context.Context, scan *module.ScanContext) error
}
```

`ScanContext` (`internal/module/module.go`) cung cấp:
- `Target string` — domain/IP
- `OutputDir string` — scan output root
- `Config *config.Config`
- `Logger zerolog.Logger`
- `Runner runner.Runner` — execute external tools
- `Results *ScanResults` — thread-safe shared state (Subdomains, LiveHosts, URLs, Findings)

`Finding` struct (lưu vào Results):
```go
type Finding struct {
    Module   string   // "http_smuggling"
    Type     string   // "vuln" / "subdomain" / "url" / "info"
    Severity string   // info / low / medium / high / critical
    Target   string   // URL hoặc host
    Detail   string   // Nội dung mô tả
}
```

Helper functions trong mỗi package: `readLines(path)`, `writeLines(path, lines)`, `replaceFUZZ(u)`.

### 1.3. Coverage theo từng phase

| Phase | Bash functions | Go modules | Coverage | Priority |
|-------|---------------|------------|----------|----------|
| **OSINT** | 14 | 9 | **64%** | Medium |
| **Subdomain** | 21 | 18 | **~86%** | Low |
| **Web** | 30 | 15 | **50%** | **HIGH** |
| **Vuln** | 13 | 15 | **100%** ✓ | Done |
| **Total** | 78 | 57 | **~73%** | |

### 1.4. Đã implement (không cần làm lại)

**OSINT (9):** `EmailHarvest`, `GoogleDorks`, `GithubLeaks`, `CloudEnum`, `SPFDMARCCheck`, `GithubDorks`, `DomainInfo`, `APILeaks`, `SpoofCheck`

**Subdomain (18):** `Subfinder`, `CrtSh`, `GithubSubdomains`, `DNSBrute`, `Permutation`, `Resolver`, `Recursive`, `TLSGrab`, `ZoneTransfer`, `S3Buckets`, `WildcardFilter`, `Takeover`, `ASNEnum`, `SubNoError`, `SRVEnum`, `SourceScraping`, `AnalyticsEnum`, `NSDelegation`

**Web (15):** `HTTPXProbe`, `Screenshots`, `Crawler`, `JSAnalyzer`, `WAFDetector`, `ParamDiscovery`, `PortScan`, `VirtualHosts`, `WebFuzz`, `URLChecks`, `URLGF`, `CMSScanner`, `IISShortname`, `TLSIPPivots`, `FavireconTech`

**Vuln (15):** `Nuclei`, `DalfoxXSS`, `SQLMapScan`, `SSRFScanner`, `SSLAudit`, `CRLFCheck`, `LFICheck`, `SSTICheck`, `CommandInjection`, `Bypass4xx`, `HTTPSmuggling`, `WebCache`, `FuzzParams`, `Spraying`, `NucleiDAST`

---

## 2. Modules còn thiếu (Missing — Cần implement)

### 2.1. OSINT phase (5 modules còn lại)

| # | Module | Bash function | Tool sử dụng | Priority |
|---|--------|---------------|--------------|----------|
| 1 | `GithubRepos` | `github_repos` | `enumerepo` + `gitleaks` + `trufflehog` | Medium |
| 2 | `Metadata` | `metadata` | `metagoofil` | Low |
| 3 | `IPInfo` | `ip_info` | `curl` + WhoisXML API | Medium |
| 4 | `ThirdPartyMisconfigs` | `third_party_misconfigs` | `misconfig-mapper` | Medium |
| 5 | `MailHygiene` | `mail_hygiene` | `dig`, `mxtoolbox` | Low |
| 6 | `GithubActionsAudit` | `github_actions_audit` | `gh`, custom parser | Low |

### 2.2. Subdomain phase (3 modules còn lại)

| # | Module | Bash function | Tool sử dụng | Priority |
|---|--------|---------------|--------------|----------|
| 1 | `SubRegexPermut` | `sub_regex_permut` | `gotator` với regex patterns | Medium |
| 2 | `SubIAPermut` | `sub_ia_permut` | `regulator` (AI-based) | Low |
| 3 | `GeoInfo` | `geo_info` | `asnmap`, `ipinfo` | Low |
| 4 | `SubPTRCidrs` | `sub_ptr_cidrs` | `hakrevdns`, `dnsx -ptr` | Medium |

### 2.3. Web phase (15 modules còn lại — **PRIORITY**)

| # | Module | Bash function | Tool sử dụng | Priority |
|---|--------|---------------|--------------|----------|
| 1 | `CDNProvider` | `cdnprovider` | `cdncheck` | **HIGH** |
| 2 | `ServiceFingerprint` | `service_fingerprint` | `nerva` + JSON parse | **HIGH** |
| 3 | `URLExt` | `url_ext` | file extension extraction | **HIGH** |
| 4 | `GraphQLScan` | `graphql_scan` | `nuclei` graphql-detect + `gqlspection` | **HIGH** |
| 5 | `GrpcReflection` | `grpc_reflection` | `grpcurl` | Medium |
| 6 | `WebsocketChecks` | `websocket_checks` | `wscat`, custom | Medium |
| 7 | `WellKnownPivots` | `well_known_pivots` | `curl`, `/.well-known/` parse | Medium |
| 8 | `WordlistGen` | `wordlist_gen` | custom extraction | Medium |
| 9 | `WordlistGenRoboxtractor` | `wordlist_gen_roboxtractor` | `roboxtractor` | Low |
| 10 | `BrokenLinks` | `brokenLinks` | `httpx`, status code filter | Medium |
| 11 | `PasswordDict` | `password_dict` | custom wordlist gen | Low |
| 12 | `SubJSExtract` | `sub_js_extract` | `subjs`, regex | Medium |
| 13 | `JSChecks` | `jschecks` | `subjs` + `mantra` + `getjswords` | **HIGH** |
| 14 | `LLMProbe` | `llm_probe` | `nuclei` llm templates | Low |
| 15 | `NucleiCheck` | `nuclei_check` | `nuclei` (regular, not DAST) | **HIGH** |

### 2.4. Code infrastructure còn thiếu

| # | Task | Priority |
|---|------|----------|
| 1 | **E2E test harness** | **HIGH** — test real scan flow với target giả lập |
| 2 | **Tool installer/checker** | **HIGH** — `pkg/tool/` có wrapper nhưng chưa có auto-install |
| 3 | **REST API WebSocket** | Medium — hiện là stub |
| 4 | **TUI test coverage** | Medium — 0 test files |
| 5 | **Config loader validation** | Medium — cần check tất cả required fields |
| 6 | **Logging to file** (rotated) | Low |
| 7 | **Notify integration** (Discord, Telegram, Slack) | Low — có struct nhưng chưa test end-to-end |
| 8 | **Diff mode** — compare scans over time | Low |
| 9 | **Monitoring mode** (continuous scans) | Low |

---

## 3. Kế hoạch thực hiện (Implementation Plan)

### Phase 1: Web phase HIGH priority (Sprint 1 — 5 modules)

> **Goal:** Hoàn thành 5 module Web cốt lõi nhất. Mỗi module = 1 file Go, pattern giống các module hiện có.

**Ưu tiên theo thứ tự:**

#### 1.1. `NucleiCheck` (web phase — khác với `Nuclei` ở vuln phase)
- **File:** `internal/module/web/nuclei_check.go`
- **Struct:** `type NucleiCheck struct{}`
- **Dependencies:** `["httpx_probe"]`
- **RequiredTools:** `["nuclei"]`
- **Input:** `webs/webs_all.txt`
- **Logic:**
  1. Run nuclei với severity theo từng level (critical, high, medium, low, info)
  2. Parse JSON output, chia theo severity
  3. Save: `nuclei_output/{severity}_json.txt`
  4. Tạo findings cho từng match (Severity dựa trên `info.severity`)
- **Config field:** Đã có `cfg.Web.Nuclei` (bool)

#### 1.2. `CDNProvider`
- **File:** `internal/module/web/cdn.go`
- **Struct:** `type CDNProvider struct{}`
- **Dependencies:** `["httpx_probe"]`
- **RequiredTools:** `["cdncheck"]`
- **Input:** `hosts/ips.txt`
- **Logic:**
  1. Run `cdncheck -i <input> -silent -json`
  2. Parse JSON, extract CDN/WAF providers
  3. Output: `hosts/cdn_providers.txt`, separate IPs thành `hosts/origin_ips.txt` (non-CDN)
- **Config field (NEW):** `Web.CDNProvider bool` trong `config.go`

#### 1.3. `URLExt`
- **File:** `internal/module/web/urlext.go`
- **Struct:** `type URLExt struct{}`
- **Dependencies:** `["url_checks"]`
- **RequiredTools:** none (pure Go)
- **Input:** `webs/url_extract.txt`
- **Logic:**
  1. Group URLs by file extension (.js, .json, .xml, .bak, .sql, .zip, etc.)
  2. Output: `webs/url_ext_<ext>.txt` per extension
  3. Focus on sensitive extensions (sql, bak, env, config)
  4. Emit findings for suspicious extensions
- **Config field (NEW):** `Web.URLExt bool`

#### 1.4. `ServiceFingerprint`
- **File:** `internal/module/web/service_fp.go`
- **Struct:** `type ServiceFingerprint struct{}`
- **Dependencies:** `["port_scan"]`
- **RequiredTools:** `["nerva"]` (fallback: parse nmap XML)
- **Input:** `hosts/naabu_open.txt` or `hosts/portscan_active.xml`
- **Logic:**
  1. Chạy `nerva --json -l <input> -o hosts/service_fingerprints.jsonl`
  2. Nếu không có nerva, parse nmap XML fallback
  3. Output: `hosts/service_fingerprints.jsonl`
- **Config field (NEW):** `Web.ServiceFingerprint bool`

#### 1.5. `GraphQLScan`
- **File:** `internal/module/web/graphql.go`
- **Struct:** `type GraphQLScan struct{}`
- **Dependencies:** `["nuclei_check"]`
- **RequiredTools:** `["gqlspection"]` (optional)
- **Input:** `nuclei_output/*_json.txt` (các file theo severity)
- **Logic:**
  1. Parse nuclei JSON files, filter `template-id == "graphql-detect"`
  2. Extract unique endpoints từ `matched-at`/`host`
  3. Với mỗi endpoint, chạy `gqlspection -t <ep> -o vulns/graphql/<host>.json`
  4. Output: `vulns/graphql/` dir, `nuclei_output/graphql.txt`
- **Config field:** Đã có `cfg.Web.GraphQL`

### Phase 2: Web phase MEDIUM (Sprint 2 — 5 modules)

#### 2.1. `JSChecks`
- **File:** `internal/module/web/jschecks.go`
- **Tools:** `subjs`, `mantra`, `getjswords`
- **Input:** `webs/url_extract.txt` (filter .js)
- **Logic:**
  1. Extract JS URLs
  2. Run `subjs` để fetch thêm JS assets
  3. Run `mantra` để tìm secrets
  4. Run `getjswords` để extract keywords → wordlist
  5. Output: `js/js_secrets.txt`, `js/js_wordlist.txt`

#### 2.2. `BrokenLinks`
- **File:** `internal/module/web/broken_links.go`
- **Tools:** `httpx`
- **Logic:** Chạy httpx trên crawled URLs, filter status `404`/`410`, output các link vỡ.

#### 2.3. `WordlistGen`
- **File:** `internal/module/web/wordlist_gen.go`
- **Tools:** pure Go
- **Logic:** Aggregate URLs/params/subs thành custom wordlist cho target.

#### 2.4. `SubJSExtract`
- **File:** `internal/module/web/sub_js_extract.go`
- **Tools:** `subjs`
- **Logic:** Extract subdomains từ JS source files.

#### 2.5. `WellKnownPivots`
- **File:** `internal/module/web/wellknown.go`
- **Tools:** `curl` (via runner)
- **Logic:** Probe `/.well-known/security.txt`, `/.well-known/openid-configuration`, `/sitemap.xml`, `/robots.txt` để extract endpoints/domains mới.

### Phase 3: OSINT gap fill (Sprint 3 — 4 modules)

#### 3.1. `GithubRepos`
- **File:** `internal/module/osint/github_repos.go`
- **Tools:** `enumerepo`, `gitleaks`, `trufflehog`
- **Flow:** enum repos → git clone → gitleaks scan → trufflehog enrichment.
- **Output:** `osint/github_company_secrets.json`

#### 3.2. `IPInfo`
- **File:** `internal/module/osint/ip_info.go`
- **Tools:** HTTP API (WhoisXML)
- **Logic:** Gọi 3 API: reverse IP, WHOIS, IP geolocation.
- **Config:** `cfg.OSINT.WhoisXMLAPIKey`
- **Output:** `osint/ip_<ip>_relations.txt`, `osint/ip_<ip>_whois.txt`, `osint/ip_<ip>_location.txt`
- **Note:** Chỉ chạy nếu target là IP address (regex check).

#### 3.3. `ThirdPartyMisconfigs`
- **File:** `internal/module/osint/third_parties.go`
- **Tool:** `misconfig-mapper`
- **Output:** `osint/3rdparts_misconfigurations.txt`

#### 3.4. `Metadata`
- **File:** `internal/module/osint/metadata.go`
- **Tool:** `metagoofil`
- **Logic:** Download public documents → extract metadata → build user/tool list.
- **Output:** `osint/metadata/`

### Phase 4: Subdomain gap fill (Sprint 4 — 3 modules)

#### 4.1. `SubRegexPermut`
- **File:** `internal/module/subdomain/regex_permut.go`
- **Tool:** `gotator` với regex pattern extraction
- **Input:** `subdomains/subdomains.txt`
- **Logic:** Extract pattern từ subdomains hiện có → generate permutations → resolve.

#### 4.2. `SubPTRCidrs`
- **File:** `internal/module/subdomain/ptr_cidrs.go`
- **Tool:** `hakrevdns` hoặc `dnsx -ptr`
- **Input:** `hosts/asn_cidrs.txt`
- **Logic:** Reverse DNS trên toàn CIDR ranges → tìm subdomains mới.

#### 4.3. `GeoInfo`
- **File:** `internal/module/subdomain/geo_info.go`
- **Tool:** `asnmap`, IP geolocation
- **Output:** `hosts/geo_info.txt` (IP, country, ASN, org)

### Phase 5: Infrastructure & QA (Sprint 5)

#### 5.1. E2E test harness
- **File:** `test/e2e/scan_test.go`
- **Target:** `example.com` hoặc mock HTTP server
- **Coverage:**
  - Full pipeline với mocked runners (không gọi tool thật)
  - Validate output dir structure
  - Validate Findings count ≥ 0
  - Validate DAG không có cycles

#### 5.2. Tool checker/installer
- **File:** `pkg/tool/installer.go`
- **Logic:**
  - Mỗi module declare `RequiredTools()`
  - `reconforge check-tools` CLI command: liệt kê tool missing + install hints
  - Support `go install` cho Go tools, `pip install` cho Python tools, brew/apt cho binaries
- **Config field (NEW):** `General.AutoInstall bool`

#### 5.3. REST API WebSocket
- **File:** `internal/api/websocket.go`
- **Logic:** Stream scan progress real-time (phase change, module complete, finding added).
- **Library:** `nhooyr.io/websocket` (đã có trong go.mod?)

#### 5.4. TUI tests
- **File:** `internal/ui/tui_test.go`
- **Coverage:** Headless model test (key events, state transitions) — không cần TTY.

---

## 4. Hướng dẫn Implementation cho Codex

### 4.1. Quy tắc chung

1. **Không thay đổi API contract của `module.Module` interface** — mọi module mới phải conform.
2. **Mỗi module = 1 file Go** (tên file = tên module snake_case).
3. **KHÔNG sửa các module hiện có** trừ khi fix bug — tập trung vào implementation mới.
4. **Config fields** phải add vào `internal/config/config.go` cùng với mapstructure tag.
5. **Register module** trong file `register.go` tương ứng (osint/subdomain/web/vuln).
6. **Update test counts** trong file `*_test.go` khi thêm module mới:
   - `/internal/module/osint/osint_test.go:15`
   - `/internal/module/subdomain/subdomain_test.go:80,84`
   - `/internal/module/web/web_test.go:15`
   - `/internal/module/vuln/vuln_test.go:15`
   - `/internal/orchestrator/orchestrator_test.go:73`
7. **Build sau mỗi module:**
   ```bash
   GOPATH=$HOME/go /Users/duongpahm/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.9.darwin-arm64/bin/go build ./...
   ```
8. **Test sau mỗi sprint:**
   ```bash
   GOPATH=$HOME/go /Users/duongpahm/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.9.darwin-arm64/bin/go test ./...
   ```

### 4.2. Template module skeleton

```go
package web  // or osint/subdomain/vuln

import (
    "context"
    "fmt"
    "os"
    "path/filepath"
    "time"

    "github.com/reconforge/reconforge/internal/config"
    "github.com/reconforge/reconforge/internal/engine"
    "github.com/reconforge/reconforge/internal/module"
    "github.com/reconforge/reconforge/internal/runner"
)

// ModuleName [short description].
type ModuleName struct{}

func (m *ModuleName) Name() string           { return "module_name" }
func (m *ModuleName) Description() string    { return "Human-readable description" }
func (m *ModuleName) Phase() engine.Phase    { return engine.PhaseWeb }
func (m *ModuleName) Dependencies() []string { return []string{"dep_module"} }
func (m *ModuleName) RequiredTools() []string { return []string{"tool_name"} }

func (m *ModuleName) Validate(cfg *config.Config) error {
    if !cfg.Web.ModuleName {
        return fmt.Errorf("module_name disabled")
    }
    return nil
}

func (m *ModuleName) Run(ctx context.Context, scan *module.ScanContext) error {
    outDir := filepath.Join(scan.OutputDir, "webs")  // or proper subdir
    if err := os.MkdirAll(outDir, 0o755); err != nil {
        return fmt.Errorf("create output dir: %w", err)
    }

    inputFile := filepath.Join(scan.OutputDir, "webs", "webs_all.txt")
    if _, err := os.Stat(inputFile); os.IsNotExist(err) {
        scan.Logger.Info().Msg("No input for module_name; skipping")
        return nil
    }

    scan.Logger.Info().Msg("Running tool_name ...")

    result, err := scan.Runner.Run(ctx, "tool_name", []string{
        "-l", inputFile,
        "-o", filepath.Join(outDir, "output.txt"),
    }, runner.RunOpts{Timeout: 30 * time.Minute})
    if err != nil {
        scan.Logger.Warn().Err(err).Msg("tool_name failed (non-fatal)")
        return nil
    }

    // Parse result, emit findings
    for _, line := range strings.Split(string(result.Stdout), "\n") {
        if line = strings.TrimSpace(line); line == "" {
            continue
        }
        scan.Results.AddFindings([]module.Finding{{
            Module:   "module_name",
            Type:     "info",     // or vuln / subdomain / url
            Severity: "info",     // or low/medium/high/critical
            Target:   line,
            Detail:   "what was found",
        }})
    }

    scan.Logger.Info().Msg("module_name complete")
    return nil
}
```

### 4.3. Runner API cheat sheet

```go
// Run command without stdin
result, err := scan.Runner.Run(ctx, "tool", []string{"-flag", "value"}, runner.RunOpts{
    Timeout: 30 * time.Minute,
})
// result.Stdout (bytes), result.Stderr (bytes), result.ExitCode (int)

// With stdin pipe
stdin, _ := os.Open(inputFile)
defer stdin.Close()
result, err := scan.Runner.Run(ctx, "tool", args, runner.RunOpts{
    Timeout: 30 * time.Minute,
    Stdin:   stdin,
})

// Pipeline (cmd1 | cmd2)
result, err := scan.Runner.RunPipeline(ctx, [][]string{
    {"tool1", "--arg"},
    {"tool2", "-p"},
}, runner.RunOpts{Timeout: 10 * time.Minute})
```

### 4.4. Deep-mode gate pattern

Các module scan heavy phải respect deep mode:

```go
if !scan.Config.General.Deep && len(targets) > 200 {
    scan.Logger.Warn().Int("targets", len(targets)).Msg("Too many targets; skipping (use deep mode)")
    return nil
}
```

Giới hạn suggest:
- URL fuzzing: 500 (non-deep)
- Active scanning (LFI, SSTI, cmdinj): 200
- DAST (nuclei): 1500
- Passive (crt, subfinder): unlimited

### 4.5. Directory convention

```
<output_dir>/<target>/
├── .tmp/              # Scratch files (cleanup sau scan)
├── osint/             # OSINT results
├── subdomains/        # Subdomain lists
├── hosts/             # IPs, ports, service fp
├── webs/              # HTTPX probes, screenshots, crawled URLs
├── js/                # JS analysis
├── fuzzing/           # Directory fuzzing results
├── gf/                # GF pattern filtered URLs
├── nuclei_output/     # Nuclei JSON per severity
├── vulns/             # Vulnerability findings
├── cms/               # CMSeeK outputs
├── logs/              # Scan logs
└── report/            # Final reports (JSON/HTML/PDF)
```

### 4.6. Anti-patterns (KHÔNG làm)

- ❌ **KHÔNG** fatal error cho tool missing — chỉ log warn và return nil
- ❌ **KHÔNG** hardcode path (luôn dùng `filepath.Join`)
- ❌ **KHÔNG** swallow errors silently — log ít nhất 1 warn
- ❌ **KHÔNG** đọc toàn bộ file lớn vào memory — dùng `bufio.Scanner`
- ❌ **KHÔNG** dùng `os.Exec` trực tiếp — luôn qua `scan.Runner`
- ❌ **KHÔNG** tạo struct global state — dùng `ScanContext`
- ❌ **KHÔNG** emoji trong code/logs (unless user yêu cầu)
- ❌ **KHÔNG** comment về task history ("added for issue #123")

---

## 5. Milestones & Acceptance Criteria

| Sprint | Deliverable | Acceptance |
|--------|-------------|------------|
| 1 | 5 Web HIGH modules | Build pass, 62 modules registered, tests update count |
| 2 | 5 Web MEDIUM modules | Build pass, 67 modules, all tests pass |
| 3 | 4 OSINT modules | Build pass, 71 modules, OSINT coverage 93% |
| 4 | 3 Subdomain modules | Build pass, 74 modules, Subdomain 100% |
| 5 | E2E harness + tool installer | `reconforge check-tools` works, e2e test runs <30s |

**Final target:** 74 Go modules matching 78 bash functions = **~95% feature parity**.

---

## 6. Quick Reference Commands

```bash
# Build
GOPATH=$HOME/go /Users/duongpahm/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.9.darwin-arm64/bin/go build ./...

# Test all
GOPATH=$HOME/go /Users/duongpahm/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.9.darwin-arm64/bin/go test ./...

# Test with race detection
GOPATH=$HOME/go /Users/duongpahm/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.9.darwin-arm64/bin/go test -race ./...

# Add dependency
GOPATH=$HOME/go /Users/duongpahm/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.9.darwin-arm64/bin/go get github.com/foo/bar@latest
GOPATH=$HOME/go /Users/duongpahm/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.9.darwin-arm64/bin/go mod tidy

# Lint (if golangci-lint installed)
golangci-lint run ./...

# Format
gofmt -w .
goimports -w .
```

---

## 7. Reference: Original reconFTW source

- **Main entry:** `/Users/duongpahm/reconftw/reconftw.sh`
- **Modules:**
  - `/Users/duongpahm/reconftw/modules/osint.sh` (14 functions)
  - `/Users/duongpahm/reconftw/modules/subdomains.sh` (21 functions)
  - `/Users/duongpahm/reconftw/modules/web.sh` (30 functions)
  - `/Users/duongpahm/reconftw/modules/vulns.sh` (13 functions)
- **Config template:** `/Users/duongpahm/reconftw/reconftw.cfg`

Khi cần hiểu một tool làm gì, đọc bash function gốc trong các file trên để tham khảo args, flags, output format.

---

**End of plan. Ready for codex execution.**

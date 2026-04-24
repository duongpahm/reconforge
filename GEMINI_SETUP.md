# Gemini Setup Instructions — Push reconforge to GitHub

> **Mục tiêu:** Init git repo cho project reconforge và push lên `https://github.com/duongpahm/reconforge.git`.
> **Audience:** Gemini (hoặc AI/người chạy command)
> **Working directory:** `/Users/duongpahm/reconftw/reconforge/`

---

## Context

Thư mục `reconforge/` hiện tại là một Go project đã build & test xong (18/18 packages pass, ~20k LOC, 82 modules). Nó đang nằm bên trong repo cũ `reconftw/` (bash framework gốc) nhưng **chưa được init git riêng**. Ta cần tách nó ra thành repo độc lập và push lên GitHub.

Các file đã sẵn sàng:
- `README.md` — landing page giới thiệu project
- `IMPLEMENTATION_PLAN.md` — plan & module spec
- `REBUILD_STATUS.md` — progress report
- `go.mod`, `go.sum` — Go dependencies
- `cmd/`, `internal/`, `pkg/`, `test/`, `configs/`, `Makefile`

---

## Pre-flight checks (chạy trước khi init)

```bash
cd /Users/duongpahm/reconftw/reconforge

# 1. Confirm no existing .git (nếu có thì HỎI user, đừng tự xoá)
ls -la .git 2>/dev/null && echo "WARNING: .git already exists — stop and ask user" || echo "OK: no existing .git"

# 2. Confirm build still passes
go build ./... && echo "OK: build clean" || echo "FAIL: fix build first"

# 3. Confirm tests still pass
go test ./... 2>&1 | tail -20

# 4. Check for any secrets accidentally left in repo
grep -rE "(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][A-Za-z0-9]{20,}" . \
    --include="*.go" --include="*.yaml" --include="*.yml" --include="*.cfg" --include="*.env" \
    2>/dev/null | grep -v "_test.go" | grep -v "example" | head -10

# 5. Check size — github soft-limits file at 100MB, warn at 50MB
find . -type f -size +10M -not -path "./.git/*" 2>/dev/null
```

**Nếu step 1 cho thấy `.git` đã tồn tại, hoặc step 4 tìm được credential thật, HÃY DỪNG và báo lại cho user. Không tự quyết định xoá.**

---

## Tạo `.gitignore`

Trước khi `git init`, tạo `.gitignore` để tránh push rác:

```bash
cat > .gitignore <<'EOF'
# Go build artifacts
bin/
*.exe
*.test
*.out
coverage.out
coverage.html

# Scan output (user-generated)
output/
scans/
*.log

# IDE / OS
.vscode/
.idea/
.DS_Store
*.swp
*~

# Go workspace
go.work
go.work.sum

# Dependencies
vendor/

# Environment / secrets
.env
.env.local
*.pem
*.key
secrets.yaml
secrets.yml

# Cached tool outputs
.cache/
.tmp/

# Database artifacts
*.db
*.sqlite
*.sqlite3
EOF
```

---

## Git init + first commit + push

Chạy **chính xác theo thứ tự**, **dừng lại và báo nếu bất kỳ lệnh nào fail**:

```bash
# Đảm bảo đang ở đúng thư mục
cd /Users/duongpahm/reconftw/reconforge

# 1. Init local git repo
git init

# 2. Stage README trước (theo yêu cầu ban đầu)
git add README.md

# 3. First commit — chỉ README để có thể đổi branch sạch
git commit -m "first commit"

# 4. Force branch name = main (đảm bảo nhất quán với GitHub default)
git branch -M main

# 5. Add GitHub remote
git remote add origin https://github.com/duongpahm/reconforge.git

# 6. Push README lên main (thiết lập upstream tracking)
git push -u origin main
```

**Nếu step 6 yêu cầu credential:** dùng GitHub Personal Access Token (classic hoặc fine-grained với `repo` scope) làm password khi bị prompt username/password, HOẶC cài `gh` CLI trước (`gh auth login`) rồi retry.

**Nếu step 6 fail vì `rejected non-fast-forward`:** remote đã có nội dung. Dừng lại và báo user — không tự `push --force`.

---

## Second commit — push toàn bộ source

Sau khi README đã lên main, commit phần code:

```bash
# Stage toàn bộ (gitignore đã loại output/, bin/, secrets)
git add .gitignore
git add IMPLEMENTATION_PLAN.md REBUILD_STATUS.md GEMINI_SETUP.md
git add Makefile go.mod go.sum
git add cmd/ internal/ pkg/ test/ configs/ scripts/

# Chỉ add plugin/ nếu có nội dung (không phải dir rỗng)
[ -n "$(ls -A plugin/ 2>/dev/null)" ] && git add plugin/

# Verify staging không kéo nhầm file lớn / secret
git status
git diff --cached --stat | tail -20

# Commit
git commit -m "feat: initial reconforge source — 82 modules, Go port of reconFTW

- OSINT: 15 modules (email harvest, github dorks/repos/leaks, API leaks, spoof, domain info, ip info, third parties, metadata, mail hygiene)
- Subdomain: 22 modules (passive/active/recursive enum, ASN, TLS, permutations, analytics, NS delegation, PTR, takeover, wildcard filter)
- Web: 30 modules (httpx, crawler, screenshots, favirecon, CDN, port scan, service fp, vhosts, fuzz, URL GF/ext, CMS, IIS, nuclei check, graphql, grpc, websocket, LLM probe, JS checks, wordlist gen)
- Vuln: 15 modules (nuclei, nuclei DAST, XSS/SQLi/SSRF/SSL/CRLF/LFI/SSTI/cmdinj/4xx bypass/smuggling/webcache/fuzzparams/spraying)
- DAG pipeline with parallel execution, Viper config, BubbleTea TUI, gin REST API, Temporal workflows
- 27 test files, 18/18 test packages passing"

# Push source
git push
```

---

## Verification (after push)

```bash
# Confirm remote state matches local
git log --oneline -5
git remote -v
git branch -vv

# Optional: check GitHub UI reflects the push
gh repo view duongpahm/reconforge --web 2>/dev/null || \
    echo "Open in browser: https://github.com/duongpahm/reconforge"
```

---

## Rollback if something goes wrong

Nếu push sai branch / sai nội dung:

```bash
# KHÔNG dùng push --force trên public repo trừ khi user đồng ý.
# Nếu cần undo local commit: git reset --soft HEAD~1 (giữ file) hoặc git reset --hard HEAD~1 (mất file).
# Nếu cần xoá remote branch đã push nhầm: hỏi user trước.
```

---

## Không được làm (Guard rails)

- ❌ **Không** chạy `git push --force` hoặc `git push -f` trừ khi user yêu cầu rõ
- ❌ **Không** `git add secrets.*` hoặc `.env` — kể cả khi user không có .gitignore
- ❌ **Không** push `output/`, `bin/`, `.DS_Store`, `go1.22.8.darwin-arm64.tar.gz` (64MB tarball thừa)
- ❌ **Không** tự sửa commit message khác với user yêu cầu ("first commit")
- ❌ **Không** `rm -rf .git` nếu phát hiện git repo cũ — hỏi user
- ❌ **Không** thay đổi `git config --global user.email/user.name` — chỉ `git config user.email/user.name` ở scope local nếu cần
- ❌ **Không** commit file lớn hơn 50MB mà không cảnh báo user trước

---

## Nếu user yêu cầu push cả repo gốc `reconftw/` (bash legacy)

Đó là việc **KHÁC** và nằm ngoài scope của doc này. Repo gốc nằm ở `/Users/duongpahm/reconftw/` (parent của reconforge/), có thể vẫn còn untracked state. Hỏi user có muốn:
1. Push reconforge thành repo riêng (scope của doc này) — target `github.com/duongpahm/reconforge`
2. Hoặc push reconftw parent thành repo khác — target ?

**Hiện tại chỉ làm (1).**

---

## Summary — copy/paste ready block

Nếu user đã OK pre-flight checks và chỉ muốn một khối command hoàn chỉnh:

```bash
cd /Users/duongpahm/reconftw/reconforge

# .gitignore (chạy 1 lần)
cat > .gitignore <<'EOF'
bin/
output/
scans/
*.log
.vscode/
.idea/
.DS_Store
*.swp
go.work
go.work.sum
vendor/
.env
.env.local
*.pem
*.key
secrets.yaml
secrets.yml
.cache/
.tmp/
*.db
*.sqlite
*.sqlite3
coverage.out
coverage.html
EOF

# Sequence gốc user yêu cầu
git init
git add README.md
git commit -m "first commit"
git branch -M main
git remote add origin https://github.com/duongpahm/reconforge.git
git push -u origin main

# Push phần source còn lại
git add .
git commit -m "feat: initial reconforge source — 82 modules, Go port of reconFTW"
git push
```

Done — report back với commit hashes và `git log --oneline -3` output để user verify.

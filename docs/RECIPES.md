# ReconForge Workflow Recipes

> Các workflow phổ biến của pentester / bug bounty hunter, đóng gói thành recipe sẵn dùng.
> Pipe-friendly recipe ngắn xem [`PIPE_RECIPES.md`](./PIPE_RECIPES.md).

---

## Recipe 1 — Daily bug bounty hunt

Setup project 1 lần, schedule cron, alert critical, triage sáng dậy.

```bash
# Setup (1 lần)
reconforge project create acme --scope ./acme.scope
reconforge project add-target acme acme.com app.acme.com api.acme.com

# Daily run (cron 2am)
reconforge schedule add acme --cron "0 2 * * *" --profile full

# Notify on critical findings
cat > ~/.reconforge/notify.yaml <<EOF
rules:
  - match: {severity: [critical], tags: [new]}
    channels: [telegram-personal]
channels:
  telegram-personal:
    bot_token: \$TG_BOT
    chat_id: \$TG_CHAT
EOF

# Sáng dậy triage
reconforge project findings acme --since 24h --severity high,critical
```

---

## Recipe 2 — Pre-engagement quick win

30 phút quick scan trước khi vào engagement.

```bash
reconforge scan -d target.com --profile quick --tail
reconforge findings list -t target.com --severity critical,high
reconforge findings export -t target.com --format markdown -o initial-findings.md
```

---

## Recipe 3 — Burp-integrated manual hunt

Scan với traffic qua Burp Suite, sau đó replay finding qua Burp để edit/manual test.

```bash
# 1. Khởi động Burp Suite, listen :8080
# 2. Scan với traffic qua Burp
reconforge scan -d target.com --profile web --proxy http://127.0.0.1:8080

# 3. Burp Site Map populated với mọi discovered URL
# 4. Replay finding qua Burp
reconforge findings replay <id> --proxy http://127.0.0.1:8080

# 5. Tag finding sau khi confirm
reconforge findings tag <id> hot
reconforge findings note <id> -m "confirmed RCE — valid impact"
```

---

## Recipe 4 — Scope validation

Validate scope file, test URL trong scope, sync từ HackerOne.

```bash
# Validate format scope file
reconforge scope validate ./.scope

# Test URL có in-scope không
reconforge scope test ./.scope https://admin.acme.com/login

# Sync scope từ HackerOne
H1_TOKEN=xxx reconforge scope sync --from hackerone --program acme -o ./.scope

# Sync scope từ Bugcrowd
BUGCROWD_TOKEN=xxx reconforge scope sync --from bugcrowd --program acme -o ./.scope

# Scan với scope filter (out-of-scope subdomain bị skip)
reconforge scan -d acme.com --inscope ./.scope
```

---

## Recipe 5 — Diff-based regression hunt

So sánh 2 lần scan, alert những finding mới critical.

```bash
# Tuần trước
reconforge scan -d target.com --profile full

# Tuần này (sau 7 ngày)
reconforge scan -d target.com --profile full

# So sánh delta
reconforge diff -t target.com --last 2 --format md > weekly-delta.md

# Chỉ alert finding mới critical
reconforge diff -t target.com --last 2 --only-new --severity critical | \
    reconforge notify send --channel slack-urgent
```

---

## Recipe 6 — Mass URL replay với payload list

Lấy URL từ findings, replay với payload list để confirm vuln.

```bash
reconforge findings list -t target.com --type ssti --format plain | \
    while read url; do
        reconforge findings replay --url "$url" \
            --payload-file ~/payloads/ssti-jinja.txt \
            --out-dir ./replay-results/
    done

# Grep response có markers
grep -l "49" ./replay-results/*.json | head
```

---

## Recipe 7 — HackerOne submission ready

Generate H1-format markdown cho 1 finding cụ thể.

```bash
# Generate H1 template
reconforge report -t target.com \
    --template hackerone \
    --finding-id <id> \
    -o ./submit.md

# Copy/paste vào H1 → submit
cat ./submit.md
```

---

## Recipe 8 — Continuous monitoring

Monitor target liên tục, alert khi có thay đổi.

```bash
# Bật monitor mode (background daemon)
reconforge monitor start acme --interval 4h --profile passive

# Check status
reconforge monitor status

# View running daemons
reconforge schedule list

# Stop monitor
reconforge monitor stop acme
```

---

## Recipe 9 — Multi-target scan song song

Scan nhiều target cùng lúc, control concurrency.

```bash
# File targets.txt mỗi dòng 1 domain
cat > targets.txt <<EOF
acme.com
foo.com
bar.com
EOF

# Scan 3 target song song
reconforge scan -l targets.txt --parallel 3 --profile quick

# Aggregate findings
for t in $(cat targets.txt); do
    reconforge findings list -t "$t" --format ndjson
done | jq -s 'group_by(.severity) | map({sev: .[0].severity, count: length})'
```

---

## Recipe 10 — CI/CD integration

Chạy reconforge trong GitHub Actions, fail PR nếu có critical finding.

```yaml
# .github/workflows/recon.yml
name: Recon
on:
  schedule:
    - cron: "0 2 * * *"
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install reconforge
        run: |
          curl -L https://github.com/duongpahm/reconforge/releases/latest/download/reconforge-linux-amd64 -o reconforge
          chmod +x reconforge
      - name: Install tools
        run: ./reconforge tools install all
      - name: Scan
        run: ./reconforge scan -d ${{ vars.TARGET }} --profile quick
      - name: Check critical
        run: |
          # Exit code 3 = critical found, dùng để fail build
          ./reconforge findings list -t ${{ vars.TARGET }} --severity critical
          test $? -ne 3
      - name: Upload report
        uses: actions/upload-artifact@v4
        with:
          name: recon-report
          path: Recon/${{ vars.TARGET }}/report.json
```

---

## Recipe 11 — Push findings tới ticket system

Tự động push finding high/critical sang Jira hoặc GitHub Issues.

```bash
# Push sang GitHub Issues
GITHUB_TOKEN=ghp_xxx reconforge findings push -t acme \
    --to github \
    --repo acme/security \
    --severity high,critical \
    --dry-run    # Preview trước

# Confirm rồi push thật
GITHUB_TOKEN=ghp_xxx reconforge findings push -t acme \
    --to github --repo acme/security \
    --severity high,critical

# Push sang Jira
JIRA_TOKEN=xxx JIRA_HOST=acme.atlassian.net \
    reconforge findings push -t acme \
    --to jira --project SEC \
    --severity critical

# Push sang Linear
LINEAR_TOKEN=lin_xxx reconforge findings push -t acme \
    --to linear --team SEC \
    --severity critical
```

---

## Recipe 12 — Profile customization

Tự định nghĩa profile cho needs riêng.

```bash
# Copy profile có sẵn
cp configs/profiles/full.yaml configs/profiles/myhunt.yaml

# Edit disable module không cần
vim configs/profiles/myhunt.yaml

# Dùng profile mới
reconforge scan -d acme.com --profile myhunt
```

Ví dụ `myhunt.yaml`:

```yaml
modules:
  osint:
    google_dorks: { enabled: true }
    github_leaks: { enabled: true }
    metadata: { enabled: false }      # Skip metagoofil (chậm)
  subdomain:
    subfinder: { enabled: true }
    dns_brute:
      enabled: true
      wordlist: ~/.reconforge/wordlists/custom-subs.txt
  web:
    nuclei_check: { enabled: true, severity: ["high","critical"] }
    web_fuzz: { enabled: false }      # Skip fuzz (noisy)
  vuln:
    nuclei: { enabled: true }
    xss_scan: { enabled: true }
    sqli_scan: { enabled: false }     # Skip sqlmap (chậm)
```

---

## Recipe 13 — Resume after crash

Scan crash giữa chừng, resume từ checkpoint.

```bash
# Scan đang chạy thì máy crash / Ctrl+C
reconforge scan -d acme.com --profile full

# Resume từ checkpoint cuối
reconforge scan -d acme.com --resume

# Check checkpoint state
sqlite3 Recon/acme.com/state.db "SELECT name, status FROM modules WHERE status != 'complete'"
```

---

## Tài liệu liên quan

- [Pipe recipes](./PIPE_RECIPES.md) — output → pipe sang tool khác
- [Architecture](./ARCHITECTURE.md) — kiến trúc internal
- [README](../README.md) — overview + CLI reference

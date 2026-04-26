# ReconForge Pipe Recipes

Các recipe dưới đây ưu tiên output dạng `plain` hoặc `ndjson` để nối trực tiếp với tool khác.

## Re-probe findings với httpx

```bash
reconforge findings list -t x --type subdomain --format plain | httpx -status-code
```

## Feed nuclei với targets export

```bash
reconforge findings export -t x --format nuclei-targets | nuclei -t custom-templates/lfi/
```

## Severity counting với jq

```bash
reconforge findings list -t x --format ndjson | jq -s 'group_by(.severity) | map({sev: .[0].severity, count: length})'
```

## Lọc finding trước khi đẩy sang ticket queue

```bash
reconforge findings list -t x --severity high,critical --format ndjson | jq -r '.[].finding_id'
```

## Export markdown ra stdout rồi pipe sang file khác

```bash
reconforge findings export -t x --format markdown | tee findings.md
```

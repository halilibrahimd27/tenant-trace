#!/usr/bin/env bash
# The containerised demo: audit both fixture applications over real HTTP and
# publish the reports.
#
# This script deliberately does NOT fail on findings. The vulnerable
# application is supposed to fail; a non-zero exit here would stop the report
# server from ever starting, which is the opposite of the point.
set -uo pipefail

REPORT_DIR="${REPORT_DIR:-/reports}"
VULNERABLE_URL="${VULNERABLE_URL:-http://vulnerable-app:8000}"
SAFE_URL="${SAFE_URL:-http://safe-app:8000}"

mkdir -p "$REPORT_DIR/vulnerable" "$REPORT_DIR/safe"

audit() {
  local name="$1" config="$2" url="$3"
  echo "── auditing ${name} at ${url} ──"
  # --i-have-authorization is required because, inside the Compose network,
  # `vulnerable-app` is a service name rather than a loopback address — the
  # prober cannot tell that apart from a real remote host, and it refuses
  # rather than guess. Passing it here is honest: these two containers were
  # started by the same `docker compose up` as this one, by the person reading
  # this. It stays out of the Makefile and out of every example that points at
  # something you did not just start yourself.
  tenanttrace probe \
    --config "$config" \
    --base-url "$url" \
    --out "$REPORT_DIR/$name" \
    --allow-mutation \
    --i-have-authorization
  echo "   exit code: $?   (1 means confirmed findings, which is expected for the vulnerable app)"
}

audit vulnerable fixtures/tenanttrace.vulnerable.toml "$VULNERABLE_URL"
audit safe       fixtures/tenanttrace.safe.toml       "$SAFE_URL"

# A tiny index so `docker compose up -d` lands somewhere useful.
cat > "$REPORT_DIR/index.html" <<'HTML'
<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TenantTrace — demo reports</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 16px/1.6 ui-sans-serif, system-ui, sans-serif; max-width: 46rem;
         margin: 4rem auto; padding: 0 1.5rem; }
  h1 { font-size: 1.6rem; margin-bottom: .25rem; }
  p.lede { color: #6b7280; margin-top: 0; }
  ul { list-style: none; padding: 0; }
  li { border: 1px solid color-mix(in srgb, currentColor 18%, transparent);
       border-radius: .6rem; padding: 1rem 1.2rem; margin: .8rem 0; }
  a { font-weight: 600; }
  code { background: color-mix(in srgb, currentColor 10%, transparent);
         padding: .1rem .35rem; border-radius: .3rem; font-size: .9em; }
</style>
<h1>TenantTrace — demo reports</h1>
<p class="lede">Two applications with identical routes, audited over HTTP.</p>
<ul>
  <li>
    <a href="vulnerable/report.html">vulnerable_app →</a>
    <div>Manual tenant scoping with six deliberate holes. Every finding here is
    confirmed by a seeded canary, not inferred.</div>
  </li>
  <li>
    <a href="safe/report.html">safe_app →</a>
    <div>The same routes with global scoping applied correctly, plus one
    platform-admin endpoint that crosses tenants on purpose. Expected result:
    no findings, positive controls passing.</div>
  </li>
</ul>
<p>Raw run transcripts and machine-readable output sit next to each report as
<code>report.json</code> and <code>runs/&lt;timestamp&gt;/exchanges.jsonl</code>.</p>
HTML

# Surface the run's own artifacts next to the rendered reports.
find "$REPORT_DIR" -name '*.html' -o -name '*.md' -o -name '*.json' | sort
echo "── reports ready at http://127.0.0.1:8088 ──"
exit 0

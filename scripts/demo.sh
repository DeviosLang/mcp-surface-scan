#!/usr/bin/env sh
# mss demo: build a risky MCP config, scan it (config mode + source mode).
set -e
here=$(cd "$(dirname "$0")/.." && pwd)
cd "$here"

tmp=$(mktemp -d)
echo "== building fixtures =="
python3 corpus/gen.py "$tmp/risky" risky
python3 corpus/gen.py "$tmp/min" minimal

echo
echo "== config mode =="
python3 -m mss_scan "$tmp/risky" --config-only

echo
echo "== source mode (scan this tool's own tree) =="
python3 -m mss_scan . --source-only | head -6

echo
echo "== CI gate =="
python3 -m mss_scan "$tmp/risky" --fail-on high >/dev/null && echo "risky: PASS (unexpected)" || echo "risky: FAIL -> exit 1 (correct)"
python3 -m mss_scan "$tmp/min"   --fail-on high >/dev/null && echo "minimal: PASS -> exit 0 (correct)" || echo "minimal: FAIL (unexpected)"

rm -rf "$tmp"
echo
echo "done."

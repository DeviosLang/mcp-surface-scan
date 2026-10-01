from __future__ import annotations
import subprocess, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mss_scan.rules import scan_path, SEV_ORDER  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "corpus"


def build(tmp_path, kind):
    dest = tmp_path / kind
    subprocess.run([sys.executable, str(CORPUS / "gen.py"), str(dest), kind], check=True)
    return dest


def test_risky_config_fires_every_family(tmp_path):
    fs = scan_path(build(tmp_path, "risky"))
    ids = {f["id"] for f in fs}
    assert {"MCP-102", "MCP-103", "MCP-104", "MCP-105", "MCP-106", "MCP-107"} <= ids, ids


def test_minimal_config_has_no_high_or_above(tmp_path):
    fs = scan_path(build(tmp_path, "minimal"))
    assert all(SEV_ORDER[f["severity"]] > SEV_ORDER["high"] for f in fs), fs


def test_fail_on_exit_codes(tmp_path):
    for kind, expected in (("risky", 1), ("minimal", 0)):
        d = build(tmp_path, kind)
        p = subprocess.run([sys.executable, "-m", "mss_scan", str(d), "--fail-on", "high"],
                           cwd=ROOT, capture_output=True)
        assert p.returncode == expected, (kind, p.returncode)


def test_json_shape(tmp_path):
    import json
    d = build(tmp_path, "risky")
    p = subprocess.run([sys.executable, "-m", "mss_scan", str(d), "--format", "json"],
                       cwd=ROOT, capture_output=True, text=True)
    fs = json.loads(p.stdout)
    for f in fs:
        assert {"id", "title", "severity", "path", "fix"} <= set(f)


def test_sarif_shape(tmp_path):
    import json
    d = build(tmp_path, "risky")
    p = subprocess.run([sys.executable, "-m", "mss_scan", str(d), "--format", "sarif"],
                       cwd=ROOT, capture_output=True, text=True)
    doc = json.loads(p.stdout)
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "mcp-surface-scan"
    assert run["results"]

from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from .rules import RULES, SEV_ORDER, scan_path
from . import __version__

BANNER = "mcp-surface-scan {} - what does an MCP server get to do?\n"


def sarif(findings):
    rules = {}
    for f in findings:
        rules[f["id"]] = {"id": f["id"], "name": f["id"],
                          "shortDescription": {"text": f["title"]},
                          "help": {"text": f"{f['fix']} refs={','.join(f['refs'])}"}}
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "mcp-surface-scan", "rules": list(rules.values())}},
        "results": [{"ruleId": f["id"],
                     "level": {"critical": "error", "high": "error", "medium": "warning",
                               "low": "note", "info": "note"}.get(f["severity"], "note"),
                     "message": {"text": f["title"]},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["path"]}}}]}
                    for f in findings]}]}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="mss", description="report what declared MCP servers can reach")
    ap.add_argument("path", nargs="?", default=".")
    ap.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    ap.add_argument("--min", default="low", choices=list(SEV_ORDER))
    ap.add_argument("--fail-on", default="none", choices=["none"] + list(SEV_ORDER))
    a = ap.parse_args(argv)
    fs = [f for f in scan_path(Path(a.path)) if SEV_ORDER.get(f["severity"], 9) <= SEV_ORDER[a.min]]
    if a.format == "json":
        print(json.dumps(fs, indent=2))
    elif a.format == "sarif":
        print(json.dumps(sarif(fs), indent=2))
    else:
        print(BANNER.format(__version__), end="")
        if not fs:
            print("no MCP servers declared (or nothing notable about them)")
        for f in fs:
            print(f"[{f['severity']:<8}] {f['id']:<8} {f['path']}")
            print(f"           {f['title']}")
            if f["evidence"]:
                print(f"           evidence: {f['evidence'][:120]}")
    if a.fail_on != "none" and any(SEV_ORDER.get(f["severity"], 9) <= SEV_ORDER[a.fail_on] for f in fs):
        sys.exit(1)

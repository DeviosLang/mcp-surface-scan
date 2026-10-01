"""
Source-level capability scan for an MCP server.

The config tells you how a server is started; the source tells you what it can do once it is
running. This module reads the source tree and reports the capability families, so "should I mount
this?" can be answered before the first tool call.

It is regex based on purpose: it is a reviewer's first pass, not a static analyser. It reports
where a family appears, never claims that a specific call is exploitable.
"""
from __future__ import annotations
import json
import re
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", "dist", "build", ".venv", "venv", "__pycache__",
             "coverage", ".next", "target", "__tests__", "tests", "test", "spec",
             "examples", "docs"}
# test files state what the code does under test, not what the server does when mounted
TEST_FILE = re.compile(r"(?:^|/)(?:test_[^/]*|[^/]*\.(?:test|spec)\.[jt]sx?|conftest\.py)$")
SOURCE_EXT = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py"}

FAMILIES = [
    # id, severity, title, patterns, fix
    ("MCP-201", "high", "executes OS commands", [
        r"\bexec(?:Sync)?\s*\(", r"\bspawn(?:Sync)?\s*\(", r"\bexecFile\s*\(",
        r"\bpopen\s*\(", r"\bos\.system\s*\(", r"\bsubprocess\.(run|call|Popen|check_output)\s*\(",
        r"\bchild_process\b",
    ], "A server that can run commands runs them with your privileges; keep it off unless you need it."),

    ("MCP-202", "high", "writes to the filesystem", [
        r"\bfs\.writeFile", r"\bfs\.appendFile", r"\bwriteFileSync", r"\bappendFileSync",
        r"\bfs\.promises\.writeFile", r"open\([^)]*['\"][wa]\+?['\"]", r"\bunlink(?:Sync)?\s*\(",
        r"\brmdir(?:Sync)?\s*\(", r"\bfs\.rm\b",
    ], "Constrain writes to one directory; a server that writes anywhere can overwrite anything your user can."),

    ("MCP-203", "medium", "reads files outside a declared root", [
        r"\breadFile(?:Sync)?\s*\(", r"\bfs\.promises\.readFile", r"\breaddir(?:Sync)?\s*\(",
        r"\bglob\s*\(", r"\bwalk\b",
    ], "Check that paths are resolved inside a declared root (realpath, then compare)."),

    ("MCP-204", "medium", "makes network requests", [
        r"\bfetch\s*\(", r"\baxios\.", r"\bhttp\.request\s*\(", r"\bhttps\.request\s*\(",
        r"\brequests\.(get|post)\s*\(", r"\bhttpx\.(get|post)\s*\(", r"\bnode-fetch\b",
        r"\bgot\s*\(\s*[\"']",
    ], "Network egress means your prompts and tool results leave the machine; know where they go."),

    ("MCP-205", "medium", "reads credentials from the environment", [
        r"process\.env\b", r"\bos\.environ\b", r"\bgetenv\s*\(",
    ], "Prefer a credential broker over a literal in a config that syncs with the repo."),

    ("MCP-206", "high", "listens on the network / all interfaces", [
        r"\blisten\s*\([^)]*['\"]0\.0\.0\.0", r"\.listen\s*\(\s*\d+\s*,?\s*['\"]0\.0\.0\.0",
        r"\bcreateServer\s*\(", r"\bapp\.listen\s*\(",
    ], "A server that binds a port is reachable by anything on the network; bind to localhost and authenticate."),

    ("MCP-209", "medium", "runs database queries", [
        r"\.query\s*\(", r"\.execute\s*\(", r"\bexecutemany\s*\(", r"\bCREATE\s+TABLE\b",
        r"\bSELECT\s+.{0,40}\bFROM\b", r"\bpg_query\b", r"\bcursor\.execute\s*\(",
        r"\bsqlite3\.connect\b", r"\bpsycopg2?\b",
    ], "A server that runs SQL can read or destroy whatever that credential can reach; give it a "
        "read-only role scoped to one database."),

    ("MCP-207", "info", "declares tools (count)", [
        r"server\.tool\s*\(", r"@mcp\.tool\b", r"\bTool\s*\(\s*name\s*=", r"list_tools",
    ], "Every declared tool is an action the model can take without asking you."),
]


def _iter_sources(root: Path, allow_dist: bool = False):
    skip = SKIP_DIRS - ({"dist", "build"} if allow_dist else set())
    for dirpath, dirnames, filenames in __import__("os").walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.suffix in SOURCE_EXT and not TEST_FILE.search(str(p)):
                yield p


def scan_source(root: Path, max_files=4000):
    root = Path(root).resolve()
    # A published npm package ships only dist/; fall back to it when there is no source tree,
    # otherwise we would silently report "nothing" for the thing people actually install.
    allow_dist = not any(_iter_sources(root))
    counts = {fid: [] for fid, *_ in [(f[0],) for f in FAMILIES]}
    n = 0
    for p in _iter_sources(root, allow_dist=allow_dist):
        if n >= max_files:
            break
        n += 1
        try:
            text = p.read_text(errors="replace")
        except Exception:
            continue
        for fid, sev, title, pats, fix in FAMILIES:
            places = []
            for pat in pats:
                for m in re.finditer(pat, text):
                    line = text[: m.start()].count("\n") + 1
                    places.append((str(p.relative_to(root)), line))
            if places:
                counts[fid].extend(sorted(set(places)))

    out = []
    for fid, sev, title, pats, fix in FAMILIES:
        hits = counts[fid]
        if not hits:
            continue
        places = sorted(hits)[:3]
        if fid == "MCP-207":
            sev = "info"
            title = f"declares {len(hits)} tool(s)"
        out.append(dict(
            id=fid, title=title, severity=sev, path=str(root),
            evidence="; ".join(f"{f}:{l}" for f, l in places) + (f" (+{len(hits) - 3} more)" if len(hits) > 3 else ""),
            refs=["CWE-829"] if fid in ("MCP-201",) else [],
            fix=fix, count=len(hits),
        ))
    return out


def scan_package_json(root: Path):
    """Supply-chain facts from package.json / pyproject.toml."""
    out = []
    pj = root / "package.json"
    if pj.is_file():
        try:
            d = json.loads(pj.read_text(errors="replace"))
        except Exception:
            d = None
        if isinstance(d, dict):
            scripts = d.get("scripts") or {}
            for key in ("preinstall", "install", "postinstall", "prepare"):
                if key in scripts:
                    out.append(dict(id="MCP-208", title=f"package.json '{key}' runs on install",
                                    severity="high" if key != "prepare" else "medium",
                                    path=str(pj), evidence=f"{key}: {str(scripts[key])[:120]}",
                                    refs=["CWE-829"], fix="Install with --ignore-scripts on a tree you have not reviewed.",
                                    count=1))
                    break
    return out


def scan(root: Path):
    return scan_source(root) + scan_package_json(root)

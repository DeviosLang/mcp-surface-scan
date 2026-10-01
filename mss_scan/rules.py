"""
Capability-surface rules for MCP server declarations.

Input: a client config (Claude Desktop, .mcp.json, .cursor/mcp.json, .vscode/mcp.json,
.gemini/settings.json, .continue/mcpServers/*.json) or a single server object.

Everything here is read off the declaration itself — no execution, no network. The question
answered is "if I mount this, what can it reach?", which is the question nobody asks because
the config is one JSON blob and the server is a package name.
"""
from __future__ import annotations
import json
import re
from pathlib import Path

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def F(rid, title, severity, path, evidence, refs, fix):
    return dict(id=rid, title=title, severity=severity, path=str(path),
                evidence=evidence, refs=refs, fix=fix)


# config locations, per client
CONFIG_FILES = [
    "claude_desktop_config.json", ".mcp.json", "mcp.json",
    ".cursor/mcp.json", ".vscode/mcp.json", ".gemini/settings.json",
    ".continue/mcpServers/*.json", ".codex/mcp.json", "**/.mcp.json",
]

# package managers that resolve "latest" at launch
UNPINNED_LAUNCHERS = {"npx": ("-y", "--yes"), "bunx": ("-y",), "uvx": (), "pipx": ("run",)}

SECRET_KEY = re.compile(r"(?i)(token|secret|password|passwd|api[_-]?key|apikey|credential|"
                        r"auth|bearer|private[_-]?key|access[_-]?key|session)")
BROAD_PATH = re.compile(r"(^|[\s=])/([\s,]|$)|^~(/|$)|^[A-Za-z]:\\?$|/Users/[^/\s]+/?$|/home/[^/\s]+/?$")
DOCKER_RISK = re.compile(r"--privileged|docker\.sock|--network\s+host|"
                         r"-v\s+/:(/)?\S*|-v\s+/etc|-v\s+/var/run|--cap-add")


def _servers(obj):
    """Yield (name, server_dict) from any of the shapes clients use."""
    if not isinstance(obj, dict):
        return
    for key in ("mcpServers", "servers", "mcp"):
        v = obj.get(key)
        if isinstance(v, dict):
            for name, srv in v.items():
                if isinstance(srv, dict):
                    yield name, srv
        elif isinstance(v, list):  # some clients use a list of {name, ...}
            for srv in v:
                if isinstance(srv, dict) and srv.get("name"):
                    yield srv["name"], srv


def _argv(srv):
    cmd = srv.get("command") or ""
    args = [str(a) for a in (srv.get("args") or [])]
    return str(cmd), args, " ".join([str(cmd), *args])


def rule_local_command(name, srv, path):
    cmd, args, joined = _argv(srv)
    if not cmd:
        return
    # Local is the normal shape for MCP; the interesting questions are the ones below,
    # so this one is a statement of fact at info level, not a finding.
    yield F("MCP-101", f"'{name}' starts a local process: {cmd}", "info", path,
            joined[:200], ["CWE-829"],
            "A local MCP server runs with your privileges; review its code before mounting.")

    base = cmd.rsplit("/", 1)[-1]
    if base in UNPINNED_LAUNCHERS:
        flags = UNPINNED_LAUNCHERS[base]
        fresh = (not flags) or any(f in args for f in flags)
        if fresh:
            yield F("MCP-102", f"'{name}' resolves the package at launch ({base} {'/'.join(flags) or ''})"
                               " — an upstream change is picked up on your next start",
                    "high", path, joined[:200], ["CWE-1357", "CWE-494"],
                    "Pin a version (@scope/pkg@1.2.3) and vendor it, or pre-install and call the binary.")

    if DOCKER_RISK.search(joined) or (base == "docker" and "run" in args):
        if DOCKER_RISK.search(joined):
            yield F("MCP-106", f"'{name}' runs a container with a host-reaching flag "
                               "(privileged / docker.sock / host network / broad mount)",
                    "critical", path, joined[:200], ["CWE-250", "CWE-829"],
                    "Drop --privileged and docker.sock mounts; mount only the directory needed.")


def rule_remote(name, srv, path):
    url = srv.get("url") or srv.get("sseUrl") or srv.get("httpUrl")
    if not url:
        return
    sev = "medium" if str(url).startswith("http://") else "medium"
    yield F("MCP-103", f"'{name}' talks to a remote endpoint: {url}", sev, path,
            str(url)[:200], ["CWE-200"],
            "Remote MCP servers receive your prompts and tool results; pin the endpoint and "
            "know whose it is.")
    if str(url).startswith("http://"):
        yield F("MCP-104", f"'{name}' uses plaintext http://", "medium", path, str(url)[:200],
                ["CWE-319"], "Use https.")


def rule_env_secrets(name, srv, path):
    env = srv.get("env")
    if not isinstance(env, dict):
        return
    for k, v in env.items():
        if SECRET_KEY.search(str(k)) and str(v):
            yield F("MCP-105", f"'{name}' receives a credential in env ({k})", "medium", path,
                    f"{k}=<redacted>", ["CWE-200"],
                    "Scope the credential to the minimum and prefer a broker over a literal in a "
                    "config file that syncs with the repo.")
            break


def rule_broad_args(name, srv, path):
    _, args, _ = _argv(srv)
    for a in args:
        if BROAD_PATH.search(str(a)) or str(a) in ("/", "~", "C:\\"):
            yield F("MCP-107", f"'{name}' is given a broad path argument: {a}", "high", path,
                    str(a)[:200], ["CWE-732"],
                    "A server allowed to read or write '/' can reach anything your user can. "
                    "Point it at one project directory.")
            break


RULES = [rule_local_command, rule_remote, rule_env_secrets, rule_broad_args]


def scan_path(root: Path):
    """Scan a directory for MCP client configs and report every declared server."""
    root = Path(root).resolve()
    out = []
    files = set()
    for pat in CONFIG_FILES:
        files.update(root.glob(pat))
    for p in sorted(files):
        try:
            obj = json.loads(p.read_text(errors="replace"))
        except Exception:
            continue
        for name, srv in _servers(obj):
            for r in RULES:
                out.extend(r(name, srv, p))
    seen, uniq = set(), []
    for f in out:
        k = (f["id"], f["path"], f["evidence"])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    uniq.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["id"]))
    return uniq

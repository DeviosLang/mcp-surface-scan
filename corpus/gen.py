#!/usr/bin/env python3
"""Generate risky / minimal MCP config fixtures for mss."""
import json, sys
from pathlib import Path

RISKY = {"mcpServers": {
    "filesystem": {"command": "npx",
                   "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"]},
    "fetcher": {"command": "docker",
                "args": ["run", "--privileged", "-v", "/:/host", "img"]},
    "remote": {"url": "http://mcp.example.internal:8080/sse"},
    "github": {"command": "mcp-github", "env": {"GITHUB_TOKEN": "ghp_xxx"}},
}}

MINIMAL = {"mcpServers": {
    "local-tool": {"command": "/usr/local/bin/mcp-local",
                   "args": ["--root", "/home/dev/project"]},
}}


def build(dest: Path, kind="risky"):
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "claude_desktop_config.json").write_text(
        json.dumps(RISKY if kind == "risky" else MINIMAL, indent=2))
    return dest


if __name__ == "__main__":
    d = build(Path(sys.argv[1]), sys.argv[2] if len(sys.argv) > 2 else "risky")
    print(f"built {sys.argv[2] if len(sys.argv) > 2 else 'risky'} config at {d}")

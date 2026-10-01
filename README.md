# mcp-surface-scan (`mss`)

> **You mounted an MCP server. What did you just give it?**
> `mss` reads the config and answers that question before the server starts.

MCP servers run with your privileges, and the config that declares them is one JSON blob: a package
name, some arguments, maybe a URL, maybe a token. `mss` turns that blob into a list of capabilities —
the thing nobody reads because it is written as arguments.

```bash
pip install .                 # or: pip install mcp-surface-scan
mss ~/.config/claude          # any directory containing an MCP client config
mss . --format sarif          # SARIF 2.1.0
mss . --fail-on high          # CI gate
```

```
mcp-surface-scan 0.1.0 - what does an MCP server get to do?
[critical] MCP-106  claude_desktop_config.json
           'fetcher' runs a container with a host-reaching flag (privileged / docker.sock / host network / broad mount)
           evidence: docker run --privileged -v /:/host img
[high    ] MCP-102  claude_desktop_config.json
           'filesystem' resolves the package at launch (npx -y/--yes) — an upstream change is picked up on your next start
           evidence: npx -y @modelcontextprotocol/server-filesystem /
[high    ] MCP-107  claude_desktop_config.json
           'filesystem' is given a broad path argument: /
           evidence: /
[medium  ] MCP-104  claude_desktop_config.json
           'remote' uses plaintext http://
           evidence: http://mcp.example.internal:8080/sse
[medium  ] MCP-105  claude_desktop_config.json
           'github' receives a credential in env (GITHUB_TOKEN)
           evidence: GITHUB_TOKEN=<redacted>
```

## What it reports

| id | question it answers |
|---|---|
| `MCP-101` | does it run a local process at all? (info — that is the normal shape) |
| `MCP-102` | is the package resolved **at launch** (`npx -y`, `uvx`, …)? then upstream can change under you |
| `MCP-103/104` | does it talk to a remote endpoint, and is that endpoint plaintext? |
| `MCP-105` | is a credential passed in `env`? |
| `MCP-106` | does it run a container with `--privileged`, `docker.sock`, host network or a broad mount? |
| `MCP-107` | is it pointed at `/`, `~` or a drive root? |

Severity is deliberately uneven on purpose: "runs a local process" is `info`, because that is what
MCP servers do. The findings are the parts you can change.

## Configs it understands

`claude_desktop_config.json`, `.mcp.json`, `mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`,
`.gemini/settings.json`, `.codex/mcp.json`, `.continue/mcpServers/*.json`.

## Fixtures

```bash
python3 corpus/gen.py /tmp/risky risky && mss /tmp/risky     # every family
python3 corpus/gen.py /tmp/min minimal && mss /tmp/min       # info only
```

## Tests

```bash
pip install -e ".[dev]" && pytest -q      # 5 tests: families, severity baseline, exit codes, json/sarif
```

## Related

[agent-boundary-scan](https://github.com/DeviosLang/agent-boundary-scan) asks the sibling question
about **repositories**: what does a repository get to make an AI coding agent do?

## License

AGPL-3.0-or-later.

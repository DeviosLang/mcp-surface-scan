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

## Two modes: the config, and the source

The config tells you how a server is started; the source tells you what it can do once it runs.

```bash
mss ~/.config/claude                       # config: what each declared server is handed
mss ./some-mcp-server --source-only        # source: what the code can reach
mss ./some-mcp-server                      # both
```

Source mode reports capability families (a reviewer's first pass, regex based — it points at
places, never claims a call is exploitable):

| id | family |
|---|---|
| `MCP-201` | executes OS commands (`exec`/`spawn`/`subprocess`) |
| `MCP-202` | writes to the filesystem |
| `MCP-203` | reads files / walks directories |
| `MCP-204` | makes network requests |
| `MCP-205` | reads credentials from the environment |
| `MCP-206` | listens on the network / all interfaces |
| `MCP-207` | how many tools it declares (every one is an action the model can take) |
| `MCP-208` | package lifecycle script that runs on install |

Test files are excluded — they state what the code does under test, not what the server does when
you mount it.

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

# log-forensics-mcp

MCP server for log forensics. Allows searching and reading supported log files.

## Quick Start

### Claude Desktop

Start the server with `bunx log-forensics-mcp`, then add the remote MCP server
to Claude Desktop's configuration file:


```json
{
  "mcpServers": {
    "log-forensics": {
      "command": "npx",
      "args": ["mcp-remote", "http://localhost:3001/mcp"]
    }
  }
}
```

Restart Claude Desktop after saving the file.

### Codex

Add this to `~/.codex/config.toml`:

```toml
[mcp_servers.log-forensics]
url = "http://localhost:3001/mcp"
```

### Cursor

Add this to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "log-forensics": {
      "url": "http://localhost:3001/mcp"
    }
  }
}
```

### VS Code

Add this to `.vscode/mcp.json`:

```json
{
  "servers": {
    "log-forensics": {
      "type": "http",
      "url": "http://localhost:3001/mcp"
    }
  }
}
```

### Claude Code

Register the server from a terminal:

```sh
claude mcp add --transport http log-forensics http://localhost:3001/mcp
```

### Other clients

Use the Streamable HTTP endpoint:

```text
http://localhost:3001/mcp
```

For clients that only support launching a local command, use `mcp-remote`:

```sh
npx mcp-remote http://localhost:3001/mcp
```

## Run manually

### From npm

```sh
bunx log-forensics-mcp
```

The first run downloads the binary for your platform from [Releases](https://github.com/SebassNoob/log-forensics-mcp/releases).

It is cached in `~/.cache/log-forensics-mcp/<version>/`, or under `$XDG_CACHE_HOME` if that is set.

The server listens on `http://localhost:3001/mcp` using Streamable HTTP.

### From source

Download the binary for your platform from [Releases](https://github.com/SebassNoob/log-forensics-mcp/releases), then run it:

```sh
./log-forensics-mcp-linux-x64
```

The server listens on `http://localhost:3001/mcp`.

### From Docker

Download the `docker-image` artifact.

```sh
docker load -i image.tar
docker run --rm -p 3001:3001 -v /path/to/artefacts:/data:ro log-forensics-mcp:<version>
```

Mount the logs you want to analyse read-only.

## Contributing

See [CONTRIBUTING.md](https://github.com/SebassNoob/log-forensics-mcp/blob/master/CONTRIBUTING.md).

## License

[Evil License](https://github.com/SebassNoob/log-forensics-mcp/blob/master/LICENSE)

# log-forensics-mcp

MCP server for log forensics. Allows searching and reading supported log files.

## Run

```sh
bunx log-forensics-mcp
```

The first run downloads the binary for your platform from [Releases](https://github.com/SebassNoob/log-forensics-mcp/releases).

It is cached in `~/.cache/log-forensics-mcp/<version>/`, or under `$XDG_CACHE_HOME` if that is set.

The server listens on `http://127.0.0.1:3001`.

The MCP endpoint is `http://127.0.0.1:3001/mcp`.

## Run without bun

Download the binary for your platform from [Releases](https://github.com/SebassNoob/log-forensics-mcp/releases), then run it:

```sh
./log-forensics-mcp-linux-x64
```

This is the same binary that `bunx` downloads.

## Contributing

See [CONTRIBUTING.md](https://github.com/SebassNoob/log-forensics-mcp/blob/master/CONTRIBUTING.md).

## License

[Evil License](https://github.com/SebassNoob/log-forensics-mcp/blob/master/LICENSE)

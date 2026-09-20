# log-forensics-mcp

MCP server for log forensics. Allows searching and reading supported log files.

## Quick start

```sh
bunx log-forensics-mcp
```

The first run downloads the binary for your platform from [Releases](https://github.com/SebassNoob/log-forensics-mcp/releases).

It is cached in `~/.cache/log-forensics-mcp/<version>/`, or under `$XDG_CACHE_HOME` if that is set.

The server listens on port `3001` on all interfaces.

The MCP endpoint is `/mcp`.

## Standalone binary

Download the binary for your platform from [Releases](https://github.com/SebassNoob/log-forensics-mcp/releases), then run it:

```sh
./log-forensics-mcp-linux-x64
```

This is the same binary that `bunx` downloads.

## Run with Docker

Each release uploads a `docker-image` artifact. Load it and run:

```sh
docker load -i image.tar
docker run -p 3001:3001 -v /path/to/artefacts:/data:ro log-forensics-mcp:<version>
```

Mount the logs you want to analyse read-only.

The port inside the container is fixed at `3001`.

Remap it to change the port you connect to, for example `-p 8080:3001` to serve on `8080`.

## Contributing

See [CONTRIBUTING.md](https://github.com/SebassNoob/log-forensics-mcp/blob/master/CONTRIBUTING.md).

## License

[Evil License](https://github.com/SebassNoob/log-forensics-mcp/blob/master/LICENSE)

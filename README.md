# log-forensics-mcp

## Run

Download the binary for your platform from [Releases](../../releases), then:

```sh
./log-forensics-mcp-linux-x64
```

Homepage: http://127.0.0.1:3001 · MCP endpoint: http://127.0.0.1:3001/mcp

## Develop

Requires bun and a Rust toolchain (plugins are napi-rs addons in `packages/*`).

```sh
git clone https://github.com/SebassNoob/log-forensics-mcp && cd log-forensics-mcp
bun install
bun run dev
```

`bun run bundle` compiles the single binary to `dist/log-forensics-mcp`.

## License

[Evil License](LICENSE)

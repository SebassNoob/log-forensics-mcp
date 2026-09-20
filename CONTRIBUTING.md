# Contributing

## Requirements

bun, and a Rust toolchain.

The plugins in `packages/*` are napi-rs addons and are compiled with cargo.

## Setup

```sh
git clone https://github.com/SebassNoob/log-forensics-mcp && cd log-forensics-mcp
bun install
bun run dev
```

## Commands

`bun run build` builds every package.

`bun run bundle` compiles the single binary to `dist/log-forensics-mcp`.

`bun run check-types` runs tsgo.

`bun run lint` runs biome on the TypeScript and clippy on the Rust crates.

`bun run format` runs biome and cargo fmt.

## Layout

`apps/mcp` is the server. It is private and is never published.

`packages/*` are the plugins. Each one is its own Cargo workspace with its own target directory.

The root `package.json` is the published npm package. It ships `bin.mjs` and nothing else.

## Releasing

Run the `release` workflow from the Actions tab and pick a bump of patch, minor or major.

The workflow versions the workspace with changesets, commits, tags, builds a binary on each of the five target platforms, creates the GitHub release, then publishes to npm.

Publishing requires the `NPM_TOKEN` repository secret.

#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, renameSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

const { version, repository } = JSON.parse(
	readFileSync(new URL("./package.json", import.meta.url), "utf8"),
);

const windows = process.platform === "win32";
const target = `${windows ? "windows" : process.platform}-${process.arch}`;
const asset = `log-forensics-mcp-${target}${windows ? ".exe" : ""}`;

const cacheDir = join(
	// biome-ignore lint/suspicious/noUndeclaredEnvVars: read at runtime by the CLI
	process.env.XDG_CACHE_HOME ?? join(homedir(), ".cache"),
	"log-forensics-mcp",
	version,
);
const binary = join(cacheDir, asset);

if (!existsSync(binary)) {
	const url = `https://github.com/${repository.replace("github:", "")}/releases/download/${version}/${asset}`;
	console.error(`Downloading ${asset} ${version}...`);

	const response = await fetch(url);
	if (!response.ok) {
		console.error(`log-forensics-mcp: ${url} returned ${response.status}.`);
		process.exit(1);
	}

	mkdirSync(cacheDir, { recursive: true });
	// Downloaded to a unique path first so concurrent first runs cannot exec a partial file.
	const partial = `${binary}.${process.pid}`;
	await writeFile(partial, response.body, { mode: 0o755 });
	renameSync(partial, binary);
}

const { status, error } = spawnSync(binary, process.argv.slice(2), { stdio: "inherit" });
if (error) {
	console.error(error.message);
}
process.exit(status ?? 1);

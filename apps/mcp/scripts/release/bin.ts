#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, renameSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import {
	ASSET,
	CACHE_DIR,
	DOWNLOAD_URL,
	VERSION,
} from "./constants";

const binary = join(CACHE_DIR, ASSET);

if (!existsSync(binary)) {
	console.error(`Downloading ${ASSET} ${VERSION}...`);

	const response = await fetch(DOWNLOAD_URL);
	if (!response.ok) {
		console.error(`log-forensics-mcp: ${DOWNLOAD_URL} returned ${response.status}.`);
		process.exit(1);
	}

	const total = Number(response.headers.get("content-length"));
	async function* withProgress(body: NonNullable<Response["body"]>) {
		let done = 0;
		for await (const chunk of body) {
			done += chunk.length;
			if (total) process.stderr.write(`\r[${done}/${total} bytes] ${Math.floor((done / total) * 100)}%`);
			yield chunk;
		}
		if (total) process.stderr.write("\n");
	}

	mkdirSync(CACHE_DIR, { recursive: true });
	// Downloaded to a unique path first so concurrent first runs cannot exec a partial file.
	const partial = `${binary}.${process.pid}`;
	await writeFile(partial, withProgress(response.body!), { mode: 0o755 });
	renameSync(partial, binary);
	console.error(`Done. Wrote to ${binary}.`);
}

const { status, error } = spawnSync(binary, process.argv.slice(2), { stdio: "inherit" });
if (error) {
	console.error(error.message);
}
process.exit(status ?? 1);

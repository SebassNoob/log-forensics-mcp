import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const { repository, version } = JSON.parse(
	readFileSync(new URL("./package.json", import.meta.url), "utf8"),
);
if (!repository || !version) {
	throw new Error("Missing repository or version in package.json");
}

const isWindows = process.platform === "win32";
const target = `${isWindows ? "windows" : process.platform}-${process.arch}`;

export const VERSION = version as string;
export const ASSET = `log-forensics-mcp-${target}${isWindows ? ".exe" : ""}`;
export const CACHE_DIR = join(tmpdir(), "log-forensics-mcp", VERSION);
export const DOWNLOAD_URL = `https://github.com/${repository.replace("github:", "")}/releases/download/${VERSION}/${ASSET}`;

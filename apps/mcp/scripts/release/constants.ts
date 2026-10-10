import { readFileSync } from "node:fs";
import { WORKSPACE_ROOT } from "@/constants";

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
export const CACHE_DIR = WORKSPACE_ROOT;
export const DOWNLOAD_URL = `https://github.com/${repository.replace("github:", "")}/releases/download/${VERSION}/${ASSET}`;

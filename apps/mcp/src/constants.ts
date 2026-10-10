import { tmpdir } from "node:os";
import { join } from "node:path";
import { version } from "../../../package.json";

if (!version) {
	throw new Error("Version is not defined in package.json");
}

export const WORKSPACE_ROOT = join(tmpdir(), "log-forensics-mcp", version);
export const DATA_DIR = join(WORKSPACE_ROOT, "data");

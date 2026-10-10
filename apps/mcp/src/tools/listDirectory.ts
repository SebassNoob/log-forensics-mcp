import { lstat, readdir, realpath } from "node:fs/promises";
import { join, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import type { InferSchema, ToolMetadata } from "xmcp";
import { z } from "zod";
import { DATA_DIR } from "@/constants";
import { resolvePlugin } from "@/load";

export const schema = {
	dirPath: z.string().describe("Path to the directory to list"),
};

export const metadata: ToolMetadata = {
	name: "list_directory",
	description:
		"List entries under DATA_DIR as tab-separated columns: type and octal permissions, size in bytes, modified time, name, and the plugin that parses the file (- for directories).",
	annotations: {
		title: "List Directory",
		readOnlyHint: true,
		idempotentHint: true,
		openWorldHint: false,
	},
};

export default async function listDirectoryTool({ dirPath }: InferSchema<typeof schema>) {
	const dataDir = resolve(DATA_DIR);
	const requestedPath = resolve(dirPath);
	const accessError = `Directory access is restricted to DATA_DIR (${DATA_DIR}). Ask the user to add their files there, then retry. Open DATA_DIR: [DATA_DIR](${pathToFileURL(DATA_DIR).href})`;
	if (requestedPath !== dataDir && !requestedPath.startsWith(`${dataDir}${sep}`)) {
		throw new Error(accessError);
	}

	const [resolvedDataDir, directory] = await Promise.all([
		realpath(dataDir),
		realpath(requestedPath),
	]);
	if (directory !== resolvedDataDir && !directory.startsWith(`${resolvedDataDir}${sep}`)) {
		throw new Error(accessError);
	}

	const names = (await readdir(directory)).sort();

	const rows = await Promise.all(
		names.map(async (name) => {
			const entry = await lstat(join(directory, name));
			const type = entry.isDirectory() ? "d" : entry.isSymbolicLink() ? "l" : "-";
			const mode = (entry.mode & 0o777).toString(8).padStart(3, "0");
			const plugin = entry.isDirectory() ? "-" : resolvePlugin(join(directory, name)).name;
			return `${type}${mode}\t${entry.size}\t${entry.mtime.toISOString()}\t${name}\t${plugin}`;
		}),
	);

	const text = rows.length
		? `${dirPath}\ntype+mode\tbytes\tmodified\tname\tplugin\n${rows.join("\n")}`
		: `${dirPath} is empty`;

	return { content: [{ type: "text" as const, text }] };
}

import { lstat, readdir } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import type { InferSchema, ToolMetadata } from "xmcp";
import { z } from "zod";
import { resolvePlugin } from "@/load";

export const schema = {
	dirPath: z.string().describe("Path to the directory to list"),
};

export const metadata: ToolMetadata = {
	name: "list_directory",
	description:
		"List a directory's entries as tab-separated columns under a header row: type and octal permissions, size in bytes, modified time, name, and the plugin that parses the file (- for directories).",
	annotations: {
		title: "List Directory",
		readOnlyHint: true,
		idempotentHint: true,
		openWorldHint: false,
	},
};

export default async function listDirectoryTool({ dirPath }: InferSchema<typeof schema>) {
	if (dirPath.startsWith("~")) {
		throw new Error(
			`Please provide an absolute path instead of using ~ for home directory: ${homedir()}`,
		);
	}
	const names = (await readdir(dirPath)).sort();

	const rows = await Promise.all(
		names.map(async (name) => {
			const entry = await lstat(join(dirPath, name));
			const type = entry.isDirectory() ? "d" : entry.isSymbolicLink() ? "l" : "-";
			const mode = (entry.mode & 0o777).toString(8).padStart(3, "0");
			const plugin = entry.isDirectory() ? "-" : resolvePlugin(join(dirPath, name)).name;
			return `${type}${mode}\t${entry.size}\t${entry.mtime.toISOString()}\t${name}\t${plugin}`;
		}),
	);

	const text = rows.length
		? `${dirPath}\ntype+mode\tbytes\tmodified\tname\tplugin\n${rows.join("\n")}`
		: `${dirPath} is empty`;

	return { content: [{ type: "text" as const, text }] };
}

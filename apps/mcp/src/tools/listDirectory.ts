import { lstat, readdir } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import type { InferSchema, ToolMetadata } from "xmcp";
import { z } from "zod";

export const schema = {
	dirPath: z.string().describe("Path to the directory to list"),
};

export const metadata: ToolMetadata = {
	name: "list_directory",
	description:
		"List a directory's entries with type, octal permissions, size, and modified time, like `ls -la`.",
	annotations: {
		title: "List Directory",
		readOnlyHint: true,
		idempotentHint: true,
		openWorldHint: false,
	},
};

export default async function listDirectoryTool({ dirPath }: InferSchema<typeof schema>) {
	if (dirPath.startsWith("~")) {
		throw new Error(`Please provide an absolute path instead of using ~ for home directory: ${homedir()}`);
	}
	const names = (await readdir(dirPath)).sort();

	const rows = await Promise.all(
		names.map(async (name) => {
			const entry = await lstat(join(dirPath, name));
			const type = entry.isDirectory() ? "d" : entry.isSymbolicLink() ? "l" : "-";
			const mode = (entry.mode & 0o777).toString(8).padStart(3, "0");
			return `${type}${mode}\t${entry.size}\t${entry.mtime.toISOString()}\t${name}`;
		}),
	);

	const text = rows.length ? `${dirPath}\n${rows.join("\n")}` : `${dirPath} is empty`;

	return { content: [{ type: "text" as const, text }] };
}

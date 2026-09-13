import type { InferSchema, ToolMetadata } from "xmcp";
import { z } from "zod";
import { resolvePlugin } from "../load";

export const schema = {
	filePath: z.string().describe("Path to the log file to search"),
	searchTerm: z.string().min(1).describe("Term to look for in the file"),
	offsetRows: z.int().min(0).optional().describe("Number of rows to skip before returning matches"),
	maxRows: z.int().positive().optional().describe("Maximum number of matching rows to return"),
	maxBytes: z
		.int()
		.positive()
		.max(102400)
		.default(16384)
		.describe("Maximum number of bytes to return, at most 102400"),
};

export const metadata: ToolMetadata = {
	name: "search",
	description:
		"Search a log file and return the matching entries. Matches are dropped from the end to stay within maxBytes, so fewer than maxRows may come back.",
	annotations: {
		title: "Search",
		readOnlyHint: true,
		idempotentHint: true,
		openWorldHint: false,
	},
};

export default async function searchTool({
	filePath,
	searchTerm,
	offsetRows,
	maxRows,
	maxBytes,
}: InferSchema<typeof schema>) {
	const plugin = resolvePlugin(filePath);

	if (!plugin.tools.search) {
		throw new Error(`Plugin "${plugin.name}" does not support search.`);
	}

	const matches = await plugin.tools.search(filePath, searchTerm);

	const filteredMatches = matches.slice(
		offsetRows ?? 0,
		maxRows ? (offsetRows ?? 0) + maxRows : undefined,
	);

	const lines: string[] = [];
	let bytes = 0;
	for (const line of filteredMatches) {
		bytes += Buffer.byteLength(line) + 1; // newline joined on below
		if (lines.length && bytes > maxBytes) {
			break;
		}
		lines.push(line);
	}

	return {
		content: [
			{
				type: "text" as const,
				text: `${plugin.name}: ${
					lines.length === 0
						? `no matches for "${searchTerm}" in ${filePath}`
						: `found ${lines.length} match(es) for "${searchTerm}" in ${filePath}`
				}${bytes > maxBytes ? `, capped at ${maxBytes} bytes` : ""}
			\n${lines.join("\n")}
		`,
			},
		],
	};
}

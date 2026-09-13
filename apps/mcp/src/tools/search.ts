import type { InferSchema, ToolMetadata } from "xmcp";
import { z } from "zod";
import { resolvePlugin } from "../load";

export const schema = {
	filePath: z.string().describe("Path to the log file to search"),
	searchTerm: z
		.string()
		.min(1)
		.describe("Term to look for in the file"),
	offsetRows: z
		.int()
		.min(0)
		.optional()
		.describe("Number of rows to skip before returning matches"),
	maxRows: z
		.int()
		.positive()
		.optional()
		.describe("Maximum number of matching rows to return"),
};

export const metadata: ToolMetadata = {
	name: "search",
	description: "Search a log file and return the matching entries.",
	annotations: {
		title: "Search",
		readOnlyHint: true,
		idempotentHint: true,
		openWorldHint: false,
	},
};

export default async function searchTool({ filePath, searchTerm, offsetRows, maxRows }: InferSchema<typeof schema>) {
	const plugin = resolvePlugin(filePath);

	if (!plugin.tools.search) {
		throw new Error(`Plugin "${plugin.name}" does not support search.`);
	}

	const matches = await plugin.tools.search(filePath, searchTerm);

	const filteredMatches = matches.slice(offsetRows ?? 0, maxRows ? (offsetRows ?? 0) + maxRows : undefined);

	const text = filteredMatches.length
		? `${plugin.name}: ${filteredMatches.length} match(es) in ${filePath}\n${filteredMatches.join("\n")}`
		: `${plugin.name}: no matches for "${searchTerm}" in ${filePath}`;

	return { content: [{ type: "text" as const, text }] };
}

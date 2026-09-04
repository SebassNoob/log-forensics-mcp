import type { InferSchema, ToolMetadata } from "xmcp";
import { z } from "zod";
import { resolvePlugin } from "../load";

export const schema = {
	filePath: z.string().describe("Path to the log file to search"),
	searchTerm: z.string().min(1).describe("Term to look for in the file"),
};

export const metadata: ToolMetadata = {
	name: "search",
	description:
		"Searches a log file using whichever plugin recognises its file path. Throws if no plugin handles the path.",
	annotations: {
		title: "Search",
		readOnlyHint: true,
		idempotentHint: true,
		openWorldHint: false,
	},
};

export default async function searchTool({ filePath, searchTerm }: InferSchema<typeof schema>) {
	const plugin = resolvePlugin(filePath);
	const matches = await plugin.search(filePath, searchTerm);

	const formatted = matches.map(
		({ offset, encoding, context }) =>
			`0x${offset.toString(16).padStart(8, "0")} ${encoding}: ${context}`,
	);

	const text = formatted.length
		? `${plugin.name}: ${formatted.length} match(es) in ${filePath}\n${formatted.join("\n")}`
		: `${plugin.name}: no matches for "${searchTerm}" in ${filePath}`;

	return { content: [{ type: "text" as const, text }] };
}

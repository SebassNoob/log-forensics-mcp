import type { InferSchema, ToolMetadata } from "xmcp";
import { z } from "zod";
import { resolvePlugin } from "../load";

export const schema = {
	filePath: z.string().describe("Path to the log file to read"),
	offsetRows: z
		.number()
		.int()
		.min(0)
		.default(0)
		.describe("Number of rows to skip before reading"),
	maxRows: z
		.number()
		.int()
		.positive()
		.default(500)
		.describe("Maximum number of rows to return"),
};

export const metadata: ToolMetadata = {
	name: "read",
	description:
		"Read a slice of a log file as text lines, starting at a row offset. A row is one record of the underlying format (a csv row, an event, a packet), and the index printed on each line is its absolute position in the file.",
	annotations: {
		title: "Read",
		readOnlyHint: true,
		idempotentHint: true,
		openWorldHint: false,
	},
};

export default async function readTool({ filePath, offsetRows, maxRows }: InferSchema<typeof schema>) {
	const plugin = resolvePlugin(filePath);

	if (!plugin.tools.read) {
		throw new Error(`Plugin "${plugin.name}" does not support read.`);
	}

	const lines = await plugin.tools.read(filePath, offsetRows, maxRows);

	const text = lines.length
		? `${plugin.name}: ${lines.length} line(s) from ${filePath} at row ${offsetRows}\n${lines.join("\n")}`
		: `${plugin.name}: nothing to read in ${filePath} at row ${offsetRows}`;

	return { content: [{ type: "text" as const, text }] };
}

import type { InferSchema, ToolMetadata } from "xmcp";
import { z } from "zod";
import { resolvePlugin } from "../load";

export const schema = {
	filePath: z.string().describe("Path to the log file to read"),
	offsetBytes: z
		.number()
		.int()
		.min(0)
		.default(0)
		.describe("Approximate byte offset to start reading from"),
	maxBytes: z
		.number()
		.int()
		.positive()
		.default(65536)
		.describe("Approximate maximum number of bytes to return"),
};

export const metadata: ToolMetadata = {
	name: "read",
	description:
		"Read a slice of a log file as text lines, starting at a byte offset. Both offset and maxBytes are estimates over the formatted output rather than exact positions in the file, so a slice may start and end a little outside the range asked for.",
	annotations: {
		title: "Read",
		readOnlyHint: true,
		idempotentHint: true,
		openWorldHint: false,
	},
};

export default async function readTool({ filePath, offsetBytes, maxBytes }: InferSchema<typeof schema>) {
	const plugin = resolvePlugin(filePath);

	if (!plugin.tools.read) {
		throw new Error(`Plugin "${plugin.name}" does not support read.`);
	}

	const lines = await plugin.tools.read(filePath, offsetBytes, maxBytes);

	const text = lines.length
		? `${plugin.name}: ${lines.length} line(s) from ${filePath} at offset ${offsetBytes}\n${lines.join("\n")}`
		: `${plugin.name}: nothing to read in ${filePath} at offset ${offsetBytes}`;

	return { content: [{ type: "text" as const, text }] };
}

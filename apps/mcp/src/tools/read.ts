import type { InferSchema, ToolMetadata } from "xmcp";
import { z } from "zod";
import { resolvePlugin } from "../load";

export const schema = {
	filePath: z.string().describe("Path to the log file to read"),
	offset: z.number().int().min(0).default(0).describe("Byte offset to start reading from"),
	maxBytes: z
		.number()
		.int()
		.positive()
		.default(65536)
		.describe("Maximum number of bytes to return"),
};

export const metadata: ToolMetadata = {
	name: "read",
	description: "Read a slice of a log file as text lines, starting at a byte offset.",
	annotations: {
		title: "Read",
		readOnlyHint: true,
		idempotentHint: true,
		openWorldHint: false,
	},
};

export default async function readTool({ filePath, offset, maxBytes }: InferSchema<typeof schema>) {
	const plugin = resolvePlugin(filePath);

	if (!plugin.tools.read) {
		throw new Error(`Plugin "${plugin.name}" does not support read.`);
	}

	const lines = await plugin.tools.read(filePath, offset, maxBytes);

	const text = lines.length
		? `${plugin.name}: ${lines.length} line(s) from ${filePath} at offset ${offset}\n${lines.join("\n")}`
		: `${plugin.name}: nothing to read in ${filePath} at offset ${offset}`;

	return { content: [{ type: "text" as const, text }] };
}

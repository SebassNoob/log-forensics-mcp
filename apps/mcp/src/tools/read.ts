import type { InferSchema, ToolMetadata } from "xmcp";
import { z } from "zod";
import { resolvePlugin } from "../load";

export const schema = {
	filePath: z.string().describe("Path to the log file to read"),
	offsetRows: z.number().int().min(0).default(0).describe("Number of rows to skip before reading"),
	maxRows: z.number().int().positive().default(500).describe("Maximum number of rows to return"),
	maxBytes: z
		.number()
		.int()
		.positive()
		.max(102400)
		.default(16384)
		.describe("Maximum number of bytes to return, at most 102400"),
};

export const metadata: ToolMetadata = {
	name: "read",
	description:
		"Read a slice of a log file as text lines, starting at a row offset. A row is one record of the underlying format (a csv row, an event, a packet), and the index printed on each line is its absolute position in the file. Rows are dropped from the end of the slice to stay within maxBytes, so fewer rows than maxRows may come back.",
	annotations: {
		title: "Read",
		readOnlyHint: true,
		idempotentHint: true,
		openWorldHint: false,
	},
};

export default async function readTool({
	filePath,
	offsetRows,
	maxRows,
	maxBytes,
}: InferSchema<typeof schema>) {
	const plugin = resolvePlugin(filePath);

	if (!plugin.tools.read) {
		throw new Error(`Plugin "${plugin.name}" does not support read.`);
	}

	const lines: string[] = [];
	let bytes = 0;
	for (const line of await plugin.tools.read(filePath, offsetRows, maxRows)) {
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
						? `nothing to read in ${filePath} at row ${offsetRows}`
						: `read ${lines.length} row(s) from ${filePath} at row ${offsetRows}`
				}${bytes > maxBytes ? `, capped at ${maxBytes} bytes` : ""}
			\n${lines.join("\n")}
		`,
			},
		],
	};
}

import type { InferSchema, ToolMetadata } from "xmcp";
import { z } from "zod";
import { resolvePlugin } from "../load";

export const schema = {
	filePath: z.string().describe("Path to the log file to describe"),
};

export const metadata: ToolMetadata = {
	name: "stat",
	description: "Get a log file's format, size, timestamps, and format-specific metadata.",
	annotations: {
		title: "Stat",
		readOnlyHint: true,
		idempotentHint: true,
		openWorldHint: false,
	},
};

export default async function statTool({ filePath }: InferSchema<typeof schema>) {
	const plugin = resolvePlugin(filePath);

	if (!plugin.tools.stat) {
		throw new Error(`Plugin "${plugin.name}" does not support stat.`);
	}

	const stat = await plugin.tools.stat(filePath);

	return {
		content: [
			{
				type: "text" as const,
				text: `${plugin.name}: ${filePath}\n${JSON.stringify(stat, null, 2)}`,
			},
		],
	};
}

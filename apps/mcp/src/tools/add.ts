import { add } from "evtx";
import type { InferSchema, ToolMetadata } from "xmcp";
import { z } from "zod";

export const schema = {
	left: z.number().int().describe("Left operand"),
	right: z.number().int().describe("Right operand"),
};

export const metadata: ToolMetadata = {
	name: "add",
	description: "Adds two integers using the native evtx addon",
	annotations: {
		title: "Add",
		readOnlyHint: true,
		idempotentHint: true,
		openWorldHint: false,
	},
};

export default function addTool({ left, right }: InferSchema<typeof schema>) {
	return {
		content: [{ type: "text" as const, text: String(add(left, right)) }],
	};
}

import type { ToolMetadata } from "xmcp";
import { plugins } from "../load";

export const metadata: ToolMetadata = {
	name: "list_supported_formats",
	description: "List the log formats this server can handle.",
	annotations: {
		title: "List Supported Formats",
		readOnlyHint: true,
		idempotentHint: true,
		openWorldHint: false,
	},
};

export default function listSupportedFormatsTool() {
	const text = plugins.map((plugin) => `${plugin.name}: ${plugin.description}`).join("\n");

	return { content: [{ type: "text" as const, text: text || "No plugins registered." }] };
}

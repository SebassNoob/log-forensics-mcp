import type { RspackOptions } from "@rspack/core";
import type { XmcpConfig } from "xmcp";

const config: XmcpConfig = {
	// xmcp resolves host at build time; 127.0.0.1 is unreachable from outside a container.
	http: { host: "0.0.0.0" },
	paths: {
		tools: "./src/tools",
		prompts: "./src/prompts",
		resources: false,
	},
	bundler: (config: RspackOptions): RspackOptions => ({
		...config,
		// dont split the output into multiple chunks, because the MCP server is a single entrypoint
		output: { ...config.output, asyncChunks: false },
		externals: [
			...(Array.isArray(config.externals) ? config.externals : []),
			// The native addon is loaded by napi-rs at runtime; rspack cannot parse .node binaries.
			{
				"csv-plugin": "commonjs csv-plugin",
				"evtx-plugin": "commonjs evtx-plugin",
				"journal-plugin": "commonjs journal-plugin",
				"pcap-plugin": "commonjs pcap-plugin",
				"reg-plugin": "commonjs reg-plugin",
				"plaintext-plugin": "commonjs plaintext-plugin",
			},
		],
	}),
	template: {
		name: "log-forensics-mcp",
		description: "MCP server for log forensics. Allows searching and reading supported log files.",
		instructions: `Call \`list_directory\` and \`list_supported_formats\` first.

Use \`search\` and \`read\` to find IOCs and build timelines.

Each format is handled by one plugin.

The server picks the first plugin that matches the path.

\`stat\` reports that plugin, plus size, timestamps, and format-specific metadata.

A plugin need not implement every tool. An unsupported call errors with the plugin name.

\`read\` and \`search\` return rows. A row is one record of the format (a csv row, an event, a packet), not one line of the file.`,
	},
};

export default config;

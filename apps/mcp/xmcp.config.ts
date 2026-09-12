import type { RspackOptions } from "@rspack/core";
import type { XmcpConfig } from "xmcp";

const config: XmcpConfig = {
	http: true,
	stdio: true,
	paths: {
		tools: "./src/tools",
		prompts: "./src/prompts",
		resources: false,
	},
	bundler: (config: RspackOptions): RspackOptions => ({
		...config,
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
		instructions:
			"You should call `list_directory` and `list_supported_formats` to see what you can do. Search for IOCs and construct timelines with the tools `search` and `read`.",
	},
};

export default config;

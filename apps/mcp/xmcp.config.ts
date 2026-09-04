import type { RspackOptions } from "@rspack/core";
import type { XmcpConfig } from "xmcp";

const config: XmcpConfig = {
	http: true,
	paths: {
		tools: "./src/tools",
		prompts: false,
		resources: false,
	},
	bundler: (config: RspackOptions): RspackOptions => ({
		...config,
		externals: [
			...(Array.isArray(config.externals) ? config.externals : []),
			// The native addon is loaded by napi-rs at runtime; rspack cannot parse .node binaries.
			{ evtx: "commonjs evtx" },
		],
	}),
	template: {
		name: "log-forensics-mcp",
		description: "MCP server for log forensics",
	},
};

export default config;

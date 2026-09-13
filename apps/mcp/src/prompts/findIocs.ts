import type { InferSchema, PromptMetadata } from "xmcp";
import { z } from "zod";

export const schema = {
	dirPath: z.string().describe("Absolute path to the directory of logs to sweep"),
	iocs: z.string().describe("Indicators to hunt for, separated by commas or newlines"),
};

export const metadata: PromptMetadata = {
	name: "find_iocs",
	title: "Find IOCs",
	description: "Sweep every log under a directory for a list of indicators of compromise.",
};

export default function findIocsPrompt({ dirPath, iocs }: InferSchema<typeof schema>) {
	const indicators = iocs
		.split(/[\n,]/)
		.map((ioc) => ioc.trim())
		.filter(Boolean)
		.map((ioc) => `- ${ioc}`)
		.join("\n");

	return `Search logs in ${dirPath} for these indicators:
${indicators}

1. Call list_directory on ${dirPath}, then on every subdirectory it reports, until you have the full file list.
2. Call stat on each file to confirm the format is supported and note the period it covers.
3. Call search once per file per indicator. for an indicator with several forms (a domain and its IP, a username with and without domain prefix) search each form separately.
4. For every hit, call read around the matching offset to capture the entries before and after it.
5. Report a table of indicator, file, timestamp, and matching entry, then list the indicators with no hits and the files that could not be searched.

An indicator is only absent if every file was searched for it. Say so if your conclusions are incomplete/inconclusive rather than making a definitive statement.`;
}

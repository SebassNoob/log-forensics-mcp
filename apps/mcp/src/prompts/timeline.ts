import type { InferSchema, PromptMetadata } from "xmcp";
import { z } from "zod";

export const schema = {
	dirPath: z.string().describe("Absolute path to the directory of logs to build a timeline from"),
};

export const metadata: PromptMetadata = {
	name: "timeline",
	title: "Timeline",
	description: "Merge every log under a directory into one chronological timeline of activity.",
};

export default function timelinePrompt({ dirPath }: InferSchema<typeof schema>) {
	return `Build a single chronological timeline from the logs under ${dirPath}.

1. Call list_directory on ${dirPath} and on every subdirectory to get the full file list.
2. Call stat on each file for its format and the period it covers, and use that to decide the window the timeline should span.
3. Call read in slices over each file, extracting timestamped entries. Normalise every timestamp to UTC ISO 8601, and note the original offset wherever a file records local time.
4. Merge the entries into one ordered sequence, keeping the source file on every row so each line stays attributable.
5. Report a table of UTC timestamp, source file, host or user where known, and the event, followed by a narrative of what appears to have happened.

Call out clock skew between sources, periods where a log is silent, and any other anomalies that might affect the timeline's accuracy.`;
}

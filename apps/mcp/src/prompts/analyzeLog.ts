import type { InferSchema, PromptMetadata } from "xmcp";
import { z } from "zod";

export const schema = {
	filePath: z.string().describe("Absolute path to the log file to analyse"),
};

export const metadata: PromptMetadata = {
	name: "analyze_log",
	title: "Analyze Log",
	description: "Triage a single log file and report notable and suspicious activity.",
};

export default function analyzeLogPrompt({ filePath }: InferSchema<typeof schema>) {
	return `Analyse the log file ${filePath}.

1. Call stat to get its format, size, timestamps, and format-specific metadata.
2. Call read at offset 0 to learn the record shape and what produced the file, then read further slices spread across the file so the tail is covered as well as the head.
3. Call search for the activity that matters in this format, at minimum:
   - authentication: successful and failed logons, session opens, account lockouts
   - privilege use: administrative logons, sudo or su, group membership changes
   - persistence: service installs, scheduled tasks, unit or cron changes
   - remote access: network logons, RDP, SSH from unexpected sources
   - execution: process creation with unusual command lines or encoded arguments
   - anti-forensics: log clearing, truncation, gaps in an otherwise continuous stream
4. Report what the file is and what generated it, the period it covers, the notable events with timestamps, anything anomalous and why it stands out, and MITRE ATT&CK techniques where the evidence supports them.

Quote the raw entry behind every finding. Separate what the log shows from what you inferred, and state what the file cannot tell you.`;
}

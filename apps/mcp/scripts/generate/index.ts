import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import { generateAttackTactics, generateAttackTechniques } from "./generate-attack-data";
import { generateEventIds } from "./generate-event-ids";
import { generatePorts } from "./generate-ports";
import { generateSysmonEventIds } from "./generate-sysmon-event-ids";

const outputDir = join(__dirname, "../../generated");
const outputModel = z.array(z.record(z.string(), z.unknown()));

const datasets = {
	"attack-techniques": {
		generate: generateAttackTechniques,
		metadata: {
			name: "MITRE ATT&CK techniques",
			description:
				"Enterprise ATT&CK techniques and sub-techniques. Each entry has its technique ID, name and description.",
		},
	},
	"attack-tactics": {
		generate: generateAttackTactics,
		metadata: {
			name: "MITRE ATT&CK tactics",
			description:
				"Enterprise ATT&CK tactics, the adversary goals techniques are grouped under. Each entry has its tactic ID, name, shortname and description.",
		},
	},
	"windows-event-ids": {
		generate: generateEventIds,
		metadata: {
			name: "Windows event IDs to monitor",
			description:
				"Windows Server event IDs recommended for security monitoring. Each entry has its current and legacy event ID, criticality and a summary of what the event means.",
		},
	},
	"sysmon-event-ids": {
		generate: generateSysmonEventIds,
		metadata: {
			name: "Sysmon event IDs",
			description:
				"Event IDs written by Sysmon, the Sysinternals system monitor. Each entry has its event ID, name and a summary of what the event records.",
		},
	},
	ports: {
		generate: generatePorts,
		metadata: {
			name: "IANA service names and port numbers",
			description:
				"The IANA registry of assigned TCP and UDP ports. Each entry has its port number or range, transport protocol, service name and description.",
		},
	},
};

const main = async () =>
	Promise.all(
		Object.entries(datasets).map(async ([dataset, { generate, metadata }]) => {
			const datasetDir = join(outputDir, dataset);
			await mkdir(datasetDir, { recursive: true });

			const data = await generate();

			const validatedData = outputModel.parse(data);

			await Promise.all([
				writeFile(join(datasetDir, "index.json"), JSON.stringify(validatedData, null, "\t")),
				writeFile(join(datasetDir, "metadata.json"), JSON.stringify(metadata, null, "\t")),
			]);
		}),
	);

main().catch((error) => {
	console.error(error);
	process.exit(1);
});

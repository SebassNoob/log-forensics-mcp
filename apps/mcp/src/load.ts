import { CsvPlugin } from "csv-plugin";
import { EvtxPlugin } from "evtx-plugin";
import { JournalPlugin } from "journal-plugin";
import { PcapPlugin } from "pcap-plugin";
import { PlaintextPlugin } from "plaintext-plugin";
import { RegPlugin } from "reg-plugin";
import type { LogForensicsPlugin } from "./plugins";

// plugins in priority order
export const defaultPlugins: LogForensicsPlugin[] = [
	new EvtxPlugin(),
	new JournalPlugin(),
	new PcapPlugin(),
	new RegPlugin(),
	new CsvPlugin(),
	new PlaintextPlugin(),
];

export function resolvePlugin(filePath: string): LogForensicsPlugin {
	const plugin = defaultPlugins.find((candidate) => candidate.identify(filePath));

	if (!plugin) {
		const registered = defaultPlugins.map((candidate) => candidate.name).join(", ");
		throw new Error(
			`No plugin handles "${filePath}". Registered plugins: ${registered || "none"}.`,
		);
	}

	return plugin;
}

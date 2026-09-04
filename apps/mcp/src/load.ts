import { EvtxPlugin } from "evtx-plugin";
import type { LogForensicsPlugin } from "./plugins";

export const plugins: LogForensicsPlugin[] = [new EvtxPlugin()];

/**
 * Picks the first plugin that claims `filePath`. Detection is delegated to the
 * plugin itself, so a plugin is only ever activated for paths it recognises; an
 * unrecognised path is an error rather than a silent no-op.
 */
export function resolvePlugin(filePath: string): LogForensicsPlugin {
	const plugin = plugins.find((candidate) => candidate.identify(filePath));

	if (!plugin) {
		const registered = plugins.map((candidate) => candidate.name).join(", ");
		throw new Error(
			`No plugin handles "${filePath}". Registered plugins: ${registered || "none"}.`,
		);
	}

	return plugin;
}

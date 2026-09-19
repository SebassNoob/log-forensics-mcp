import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

type MonitoredEvent = {
	currentEventId: string | null;
	legacyEventId: string | null;
	criticality: string;
	summary: string;
};

const sourceUrl =
	"https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor";

async function fetchEventIdTableHtml(url: string): Promise<string> {
	const response = await fetch(url);
	const html = await response.text();

	if (!response.ok) {
		throw new Error(`${response.status} ${html}`);
	}

	return html;
}

function parseEventIdTable(html: string): MonitoredEvent[] {
	const section = html.split('<h2 id="event-id-table">')[1];
	if (!section) {
		throw new Error('Could not find the "Event ID table" section');
	}

	const table = section.match(/<table>[\s\S]*?<\/table>/)?.[0];
	if (!table) {
		throw new Error("Could not find a table under the Event ID table section");
	}

	const normalize = (value: string) => (value === "N/A" || value === "-" ? null : value);

	return [...table.matchAll(/<tr>([\s\S]*?)<\/tr>/g)]
		.slice(1)
		.map(([, row]) => {
			const [currentEventId, legacyEventId, criticality, summary] = [
				...row.matchAll(/<td>([\s\S]*?)<\/td>/g),
			].map((m) => m[1].trim());

			return {
				currentEventId: normalize(currentEventId),
				legacyEventId: normalize(legacyEventId),
				criticality,
				summary,
			};
		});
}

export async function generateEventIds(outputDir: string) {
	const html = await fetchEventIdTableHtml(sourceUrl);
	const events = parseEventIdTable(html);

	await mkdir(outputDir, { recursive: true });
	await writeFile(join(outputDir, "windows-event-ids.json"), JSON.stringify(events, null, "\t"));
}

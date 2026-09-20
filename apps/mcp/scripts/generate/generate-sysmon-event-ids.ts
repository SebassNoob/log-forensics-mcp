const sourceUrl = "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon";

export async function generateSysmonEventIds() {
	const response = await fetch(sourceUrl);
	const html = await response.text();

	if (!response.ok) {
		throw new Error(`${response.status} ${html}`);
	}

	const events = [
		...html.matchAll(/<h3 id="event-id-[^"]*">Event ID (\d+): ([^<]*)<\/h3>([\s\S]*?)(?=<h[23] )/g),
	].map(([, eventId, name, body]) => ({
		eventId,
		name,
		description: body
			.replace(/<[^>]*>/g, "")
			.replace(/\s+/g, " ")
			.trim(),
	}));

	if (events.length === 0) {
		throw new Error("Could not find any event sections");
	}

	return events;
}

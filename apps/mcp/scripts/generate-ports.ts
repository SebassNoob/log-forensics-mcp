const sourceUrl =
	"https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv";

// Descriptions contain commas and wrap across lines, so fields need quote tracking.
function parseCsv(text: string): string[][] {
	const rows: string[][] = [[""]];
	let quoted = false;

	for (let i = 0; i < text.length; i++) {
		const char = text[i];
		const row = rows[rows.length - 1];

		if (quoted) {
			if (char !== '"') {
				row[row.length - 1] += char;
			} else if (text[i + 1] === '"') {
				row[row.length - 1] += '"';
				i++;
			} else {
				quoted = false;
			}
		} else if (char === '"') {
			quoted = true;
		} else if (char === ",") {
			row.push("");
		} else if (char === "\n") {
			rows.push([""]);
		} else if (char !== "\r") {
			row[row.length - 1] += char;
		}
	}

	return rows;
}

export async function generatePorts() {
	const response = await fetch(sourceUrl);
	const csv = await response.text();

	if (!response.ok) {
		throw new Error(`${response.status} ${csv}`);
	}

	return parseCsv(csv)
		.slice(1)
		.flatMap((row) => {
			const [service, port, transport, description] = row.map((field) =>
				field.replace(/\s+/g, " ").trim(),
			);

			return port &&
				(service || description) &&
				!/^(reserved|unassigned|de-registered|removed)$/i.test(description)
				? [{ port, transport, service, description }]
				: [];
		});
}

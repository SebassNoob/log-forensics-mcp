import { writeFile } from "node:fs";
import { join } from "node:path";
import { promisify } from "node:util";

const writeFileAsync = promisify(writeFile);

type StixObject = {
	type: string;
	name: string;
	description?: string;
	revoked?: boolean;
	x_mitre_deprecated?: boolean;
	x_mitre_is_subtechnique?: boolean;
	x_mitre_shortname?: string;
	x_mitre_platforms?: string[];
	x_mitre_version?: string;
	kill_chain_phases?: { phase_name: string }[];
	external_references?: { source_name: string; external_id?: string; url?: string }[];
};

async function fetchAttackData(stixUrl: string): Promise<StixObject[]> {
	const response = await fetch(stixUrl);

	const body = await response.json();

	if (!response.ok) {
		throw new Error(`${response.status} ${body}`);
	}

	return body.objects;
}

async function parseAttackTechniques(
	data: StixObject[],
): Promise<{ id: string; name: string; description: string }[]> {
	const attackPattern: StixObject[] = data.filter(
		(obj: Record<string, unknown>) => "type" in obj && obj.type === "attack-pattern",
	);

	const techniques = attackPattern
		.filter((obj) => !obj.revoked && !obj.x_mitre_deprecated)
		.map((obj) => {
			const id = obj.external_references?.find(
				(r) => r.source_name === "mitre-attack",
			)?.external_id;
			return id ? { id, name: obj.name, description: obj.description ?? "" } : null;
		})
		.filter((t): t is { id: string; name: string; description: string } => t !== null);

	return techniques;
}

async function parseAttackTactics(
	data: StixObject[],
): Promise<{ id: string; name: string; shortname: string; description: string }[]> {
	const tacticObjects: StixObject[] = data.filter(
		(obj: Record<string, unknown>) => "type" in obj && obj.type === "x-mitre-tactic",
	);

	const tactics = tacticObjects
		.filter((obj) => !obj.revoked && !obj.x_mitre_deprecated)
		.map((obj) => {
			const id = obj.external_references?.find(
				(r) => r.source_name === "mitre-attack",
			)?.external_id;
			return id
				? {
						id,
						name: obj.name,
						shortname: obj.x_mitre_shortname ?? "",
						description: obj.description ?? "",
					}
				: null;
		})
		.filter(
			(t): t is { id: string; name: string; shortname: string; description: string } => t !== null,
		);

	return tactics;
}

export async function generateAttackData(outputDir: string) {
	const stixUrl =
		"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json";

	const data = await fetchAttackData(stixUrl);

	const [techniques, tactics] = await Promise.all([
		parseAttackTechniques(data),
		parseAttackTactics(data),
	]);

	await Promise.all([
		writeFileAsync(
			join(outputDir, "attack-techniques.json"),
			JSON.stringify(techniques, null, "\t"),
		),
		writeFileAsync(join(outputDir, "attack-tactics.json"), JSON.stringify(tactics, null, "\t")),
	]);
}

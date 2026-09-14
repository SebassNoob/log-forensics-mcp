import { existsSync, mkdirSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

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

const output = join(__dirname, "../generated/attack-enterprise.json");

async function main() {
	const response = await fetch(
		"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
	);

	if (!response.ok) {
		throw new Error(`${response.status} ${response.statusText}`);
	}

	const resp = await response.json();
	const attackPattern: StixObject[] = resp.objects.filter(
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

	if (!existsSync(dirname(output))) {
		mkdirSync(dirname(output), { recursive: true });
	}

	const tmp = `${output}.tmp`;
	writeFileSync(tmp, JSON.stringify(techniques, null, 2));
	renameSync(tmp, output);
}

main().catch((error) => {
	console.warn(`Skipping the ATT&CK resource, could not generate its data: ${error.message}`);
});

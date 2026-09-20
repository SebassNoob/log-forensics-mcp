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

const stixUrl =
	"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json";

// The bundle is tens of megabytes, so both generators share one fetch.
let bundle: Promise<StixObject[]> | undefined;

function fetchAttackData(): Promise<StixObject[]> {
	bundle ??= fetch(stixUrl).then(async (response) => {
		const body = await response.json();

		if (!response.ok) {
			throw new Error(`${response.status} ${body}`);
		}

		return body.objects;
	});

	return bundle;
}

const attackId = (obj: StixObject) =>
	obj.external_references?.find((r) => r.source_name === "mitre-attack")?.external_id;

export async function generateAttackTechniques() {
	const data = await fetchAttackData();

	return data
		.filter((obj) => obj.type === "attack-pattern" && !obj.revoked && !obj.x_mitre_deprecated)
		.flatMap((obj) => {
			const id = attackId(obj);
			return id ? [{ id, name: obj.name, description: obj.description ?? "" }] : [];
		});
}

export async function generateAttackTactics() {
	const data = await fetchAttackData();

	return data
		.filter((obj) => obj.type === "x-mitre-tactic" && !obj.revoked && !obj.x_mitre_deprecated)
		.flatMap((obj) => {
			const id = attackId(obj);
			return id
				? [
						{
							id,
							name: obj.name,
							shortname: obj.x_mitre_shortname ?? "",
							description: obj.description ?? "",
						},
					]
				: [];
		});
}

import { generateAttackData } from "./generate-attack-data";
import { generateEventIds } from "./generate-event-ids";
import { join } from "node:path";

const outputDir = join(__dirname, "../generated");

const main = async () => Promise.all([generateEventIds, generateAttackData].map((fn) => fn(outputDir)));

main().catch((error) => {
	console.error(error);
	process.exit(1);
});

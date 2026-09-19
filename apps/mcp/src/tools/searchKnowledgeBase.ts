import MiniSearch from "minisearch";
import type { InferSchema, ToolMetadata } from "xmcp";
import { z } from "zod";

// resolved at build time.
// @ts-expect-error
const files = import.meta.webpackContext("../../generated", {
	recursive: true,
	regExp: /\.json$/,
}) as { (key: string): unknown; keys(): string[] };

const datasets = files
	.keys()
	.filter((key) => key.endsWith("/metadata.json"))
	.map((key) => ({
		id: key.split("/")[1],
		...z.object({ name: z.string(), description: z.string() }).parse(files(key)),
	}));

const datasetIds = datasets.map((dataset) => dataset.id) as [string, ...string[]];

const index = new MiniSearch({ fields: ["text"], storeFields: ["dataset", "text"] });
index.addAll(
	datasets
		.flatMap((dataset) =>
			(files(`./${dataset.id}/index.json`) as Record<string, unknown>[]).map((entry) => ({
				dataset: dataset.id,
				text: Object.entries(entry)
					.filter(([, value]) => value !== null && value !== "")
					.map(([field, value]) => `${field}: ${value}`)
					.join("\n"),
			})),
		)
		// no field is guaranteed unique across datasets, so position is the id
		.map((entry, id) => ({ ...entry, id })),
);

export const schema = {
	query: z.string().min(1).describe('Terms to look up, such as "lsass dumping" or "4625"'),
	datasets: z
		.array(z.enum(datasetIds))
		.nonempty()
		.default(datasetIds)
		.describe("Datasets to search"),
	maxResults: z.int().positive().default(10).describe("Maximum number of entries to return"),
	maxBytes: z
		.int()
		.positive()
		.max(102400)
		.default(16384)
		.describe("Maximum number of bytes to return, at most 102400"),
};

export const metadata: ToolMetadata = {
	name: "search_knowledge_base",
	description: `Search the bundled reference data by relevance.

An entry is one record of a dataset, printed as its fields.

The datasets are:

${datasets.map((dataset) => `${dataset.id}: ${dataset.name}. ${dataset.description}`).join("\n\n")}

Entries are truncated.

Entries are dropped from the end to stay within maxBytes, so fewer than maxResults may come back.`,
	annotations: {
		title: "Search Knowledge Base",
		readOnlyHint: true,
		idempotentHint: true,
		openWorldHint: false,
	},
};

export default function searchKnowledgeBaseTool({
	query,
	datasets,
	maxResults,
	maxBytes,
}: InferSchema<typeof schema>) {
	const lines: string[] = [];
	let bytes = 0;
	for (const hit of index
		.search(query, { prefix: true, fuzzy: 0.2, filter: (r) => datasets.includes(r.dataset) })
		.slice(0, maxResults)) {
		const line = `${hit.score.toFixed(2)}\t${hit.dataset}\n${
			hit.text.length > 600 ? `${hit.text.slice(0, 600)}…` : hit.text
		}`;
		bytes += Buffer.byteLength(line) + 2; // blank line joined on below
		if (lines.length && bytes > maxBytes) {
			break;
		}
		lines.push(line);
	}

	return {
		content: [
			{
				type: "text" as const,
				text: `${
					lines.length === 0
						? `no entries match "${query}"`
						: `found ${lines.length} entr${lines.length === 1 ? "y" : "ies"} for "${query}"`
				}${bytes > maxBytes ? `, capped at ${maxBytes} bytes` : ""}\n\n${lines.join("\n\n")}`,
			},
		],
	};
}

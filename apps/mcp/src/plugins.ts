/** A single occurrence of a search term within a file. */
export interface SearchMatch {
	offset: number;
	encoding: string;
	context: string;
}

/**
 * The contract a plugin satisfies. napi-rs generates classes in exactly this
 * shape from a plugin crate, so a native addon is registered directly with no
 * adapter in between.
 */
export interface LogForensicsPlugin {
	readonly name: string;
	readonly description: string;
	identify(filePath: string): boolean;
	search(filePath: string, searchTerm: string): Promise<SearchMatch[]>;
}

export interface LogForensicsPlugin {
	readonly name: string;
	readonly description: string;
	identify(filePath: string): boolean;
	tools: {
		search?(filePath: string, searchTerm: string): Promise<string[]>;
		read?(filePath: string, offset: number, max_bytes: number): Promise<string[]>;
		stat?(filePath: string): Promise<Record<string, unknown>>;
	};
}

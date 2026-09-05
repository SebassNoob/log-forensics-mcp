
type OptionalPromise<T> = Promise<T> | T;
type Serializable = string | number | boolean | null | Serializable[] | { [key: string]: Serializable };

export interface LogForensicsPlugin {
	readonly name: string;
	readonly description: string;
	identify(filePath: string): OptionalPromise<boolean>;
	tools: {
		search?(filePath: string, searchTerm: string): OptionalPromise<string[]>;
		read?(filePath: string, offset: number, max_bytes: number): OptionalPromise<string[]>;
		stat?(filePath: string): OptionalPromise<{
            format: string;
            sizeBytes: number;
            modifiedAt: string;
            createdAt: string;
            metadata?: Record<string, Serializable>;
        }>;
	};
}

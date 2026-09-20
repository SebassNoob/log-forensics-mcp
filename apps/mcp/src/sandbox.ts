import { lstat, mkdir, realpath } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative, resolve, sep, win32 } from "node:path";
import envPaths from "env-paths";

// Windows device names, which open a console or a serial port instead of a file.
const RESERVED = /(^|[/\\])(con|prn|aux|nul|com[1-9]|lpt[1-9])([.\\/]|$)/i;

let root: Promise<string> | undefined;

export function sandboxRoot(): Promise<string> {
	root ??= (async () => {
		// suffix defaults to "nodejs", which would append it to the directory name.
		const data = envPaths("log-forensics-mcp", { suffix: "" }).data;
		await mkdir(data, { recursive: true });
		return realpath(data);
	})();
	return root;
}

// isAbsolute catches a windows junction that realpath followed onto another drive.
function contain(root: string, target: string, input: string) {
	const rel = relative(root, target);
	if (rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) {
		throw new Error(`"${input}" resolves outside the workspace root ${root}.`);
	}
}

// realpath rejects a path that does not exist yet, so canonicalise the deepest existing
// ancestor and re-attach the rest. The caller checks containment first, so the walk stops
// at the workspace root at the latest.
async function canonicalize(target: string): Promise<string> {
	try {
		return await realpath(target);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
			throw error;
		}
		return join(await canonicalize(dirname(target)), basename(target));
	}
}

export async function resolveInSandbox(input: string): Promise<string> {
	const root = await sandboxRoot();

	// win32.parse reads drive letters and UNC prefixes on every platform, so it rejects
	// "C:x" and "\\\\host\\share" as well as the plain absolute paths isAbsolute would catch.
	if (input.startsWith("~") || input.includes("\0") || win32.parse(input).root) {
		throw new Error(`Paths are relative to the workspace root ${root}. Got "${input}".`);
	}
	if (RESERVED.test(input)) {
		throw new Error(`"${input}" names a reserved device.`);
	}

	const resolved = resolve(root, input);
	contain(root, resolved, input);

	const canonical = await canonicalize(resolved);
	contain(root, canonical, input);

	return canonical;
}

export async function resolveFileInSandbox(input: string): Promise<string> {
	const path = await resolveInSandbox(input);
	const entry = await lstat(path);

	if (!entry.isFile()) {
		throw new Error(
			`"${input}" is ${entry.isDirectory() ? "a directory" : "a special file"}, not a regular file.`,
		);
	}

	return path;
}

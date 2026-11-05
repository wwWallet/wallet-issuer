import { ClaimMetadataEntry, TypeMetadata } from 'wallet-common';

export type DisclosureFrame = {
	_sd?: Array<string | number>;
	[key: string]: unknown;
};

const protectedClaims = new Set([
	'iss',
	'nbf',
	'exp',
	'cnf',
	'vct',
	'vct#integrity',
	'aka_vcts',
	'status',
]);

const resolvePath = (
	value: unknown,
	path: ClaimMetadataEntry['path'],
	index = 0,
	resolved: Array<string | number> = [],
): Array<Array<string | number>> => {
	if (index === path.length) return [resolved];

	const segment = path[index];
	if (segment === null) {
		if (!Array.isArray(value)) {
			throw new Error(`Invalid Type Metadata path ${JSON.stringify(path)}: expected an array`);
		}
		return value.flatMap((item, itemIndex) =>
			resolvePath(item, path, index + 1, [...resolved, itemIndex]),
		);
	}

	if (Array.isArray(value)) {
		if (typeof segment !== 'number') {
			throw new Error(
				`Invalid Type Metadata path ${JSON.stringify(path)}: array segment must be a number`,
			);
		}
		if (!Object.prototype.hasOwnProperty.call(value, segment)) return [];
		return resolvePath(value[segment], path, index + 1, [...resolved, segment]);
	}

	if (typeof value !== 'object' || value === null) {
		throw new Error(`Invalid Type Metadata path ${JSON.stringify(path)}: expected an object`);
	}
	if (typeof segment !== 'string') {
		throw new Error(
			`Invalid Type Metadata path ${JSON.stringify(path)}: object segment must be a string`,
		);
	}
	if (!Object.prototype.hasOwnProperty.call(value, segment)) return [];

	return resolvePath((value as Record<string | number, unknown>)[segment], path, index + 1, [
		...resolved,
		segment,
	]);
};

const addPath = (frame: DisclosureFrame, path: Array<string | number>) => {
	let current = frame;

	for (const segment of path.slice(0, -1)) {
		const key = String(segment);
		if (!Object.prototype.hasOwnProperty.call(current, key)) {
			Object.defineProperty(current, key, {
				value: {},
				enumerable: true,
				writable: true,
			});
		}
		current = current[key] as DisclosureFrame;
	}

	const claim = path.at(-1);
	if (claim === undefined) return;
	current._sd ??= [];
	if (!current._sd.includes(claim)) current._sd.push(claim);
};

export const createDisclosureFrame = (
	payload: Record<string, unknown>,
	typeMetadata: TypeMetadata,
): DisclosureFrame => {
	const frame: DisclosureFrame = {};

	for (const claim of typeMetadata.claims ?? []) {
		if (claim.sd === 'never') continue;
		const rootClaim = claim.path[0];
		if (typeof rootClaim === 'string' && protectedClaims.has(rootClaim)) {
			throw new Error(`Protected claim '${rootClaim}' cannot be selectively disclosable`);
		}
		for (const path of resolvePath(payload, claim.path)) addPath(frame, path);
	}

	return frame;
};

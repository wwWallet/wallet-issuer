import { inflateSync } from 'node:zlib';
import { importX509, jwtVerify, JWTPayload } from 'jose';
import { fromBase64Url, verifyX5C } from 'wallet-common';

export type KeyAttestationRequirements = {
	key_storage?: string[];
	user_authentication?: string[];
};

export function validateKeyAttestationAssurance(
	payload: JWTPayload,
	requirements: KeyAttestationRequirements | undefined,
): string | null {
	if (!requirements) {
		return null;
	}
	for (const [claimName, acceptedValues] of [
		['key_storage', requirements.key_storage],
		['user_authentication', requirements.user_authentication],
	] as const) {
		if (!acceptedValues) {
			continue;
		}
		const assertedValues = payload[claimName];
		if (
			!Array.isArray(assertedValues) ||
			!assertedValues.every(value => typeof value === 'string') ||
			!assertedValues.some(value => acceptedValues.includes(value))
		) {
			return `Key attestation does not satisfy the '${claimName}' requirement`;
		}
	}
	return null;
}

export async function validateKeyAttestationStatus(
	payload: JWTPayload,
	trustedCertificates: string[],
	options: {
		fetchStatusList?: typeof fetch;
		timeoutMilliseconds?: number;
	} = {},
): Promise<string | null> {
	const keyStorageStatus = asRecord(payload.key_storage_status);
	if (!keyStorageStatus) {
		return null;
	}
	if (typeof keyStorageStatus.exp !== 'number' || keyStorageStatus.exp <= Math.floor(Date.now() / 1000)) {
		return 'Key attestation storage status has expired';
	}
	const status = asRecord(keyStorageStatus.status);
	const statusListReference = asRecord(status?.status_list);
	if (
		!statusListReference ||
		typeof statusListReference.uri !== 'string' ||
		!Number.isSafeInteger(statusListReference.idx) ||
		(statusListReference.idx as number) < 0
	) {
		return 'Key attestation contains an invalid status list reference';
	}

	let statusListUrl: URL;
	try {
		statusListUrl = new URL(statusListReference.uri);
		assertStatusListUrlAllowed(statusListUrl);
	}
	catch {
		return 'Key attestation contains an unsafe status list URI';
	}

	const controller = new AbortController();
	const timeout = setTimeout(() => controller.abort(), options.timeoutMilliseconds ?? 5000);
	try {
		const response = await (options.fetchStatusList ?? fetch)(statusListUrl, {
			headers: { Accept: 'application/statuslist+jwt' },
			signal: controller.signal,
		});
		if (!response.ok) {
			return `Key attestation status list returned HTTP ${response.status}`;
		}
		const token = await response.text();
		if (token.length === 0 || token.length > 256 * 1024) {
			return 'Key attestation status list has an invalid size';
		}
		const [encodedHeader] = token.split('.');
		const header = asRecord(JSON.parse(new TextDecoder().decode(fromBase64Url(encodedHeader))));
		if (
			!header ||
			header.typ !== 'statuslist+jwt' ||
			typeof header.alg !== 'string' ||
			!Array.isArray(header.x5c) ||
			!header.x5c.every(value => typeof value === 'string') ||
			header.x5c.length === 0
		) {
			return 'Key attestation status list has an invalid JOSE header';
		}
		if (!await verifyX5C(header.x5c as string[], trustedCertificates)) {
			return 'Key attestation status list is not signed by a trusted Wallet Provider';
		}
		const leafCertificate = toPemCertificate(header.x5c[0] as string);
		const publicKey = await importX509(leafCertificate, header.alg);
		const verified = await jwtVerify(token, publicKey, {
			algorithms: [header.alg],
			subject: statusListUrl.toString(),
		});
		if (verified.protectedHeader.typ !== 'statuslist+jwt') {
			return 'Key attestation status list has an invalid type';
		}
		return decodeStatusListEntry(verified.payload, statusListReference.idx as number)
			? 'Key attestation has been revoked'
			: null;
	}
	catch {
		return 'Key attestation status list could not be verified';
	}
	finally {
		clearTimeout(timeout);
	}
}

export function decodeStatusListEntry(payload: JWTPayload, index: number): boolean {
	const statusList = asRecord(payload.status_list);
	if (!statusList || statusList.bits !== 1 || typeof statusList.lst !== 'string') {
		throw new Error('Invalid status list payload');
	}
	const bytes = inflateSync(Buffer.from(statusList.lst, 'base64url'));
	if (index >= bytes.length * 8) {
		throw new Error('Status list index is out of bounds');
	}
	return ((bytes[Math.floor(index / 8)] >> (index % 8)) & 1) === 1;
}

function assertStatusListUrlAllowed(url: URL): void {
	if (url.protocol === 'https:') {
		return;
	}
	const loopbackHosts = new Set(['localhost', '127.0.0.1', '[::1]']);
	if (url.protocol === 'http:' && process.env.NODE_ENV !== 'production' && loopbackHosts.has(url.hostname)) {
		return;
	}
	throw new Error('Status list URI must use HTTPS');
}

function toPemCertificate(value: string): string {
	const lines = value.match(/.{1,64}/g);
	if (!lines) {
		throw new Error('Invalid x5c certificate');
	}
	return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----`;
}

function asRecord(value: unknown): Record<string, unknown> | null {
	return typeof value === 'object' && value !== null && !Array.isArray(value)
		? value as Record<string, unknown>
		: null;
}

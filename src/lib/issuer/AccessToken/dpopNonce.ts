import { createHmac, timingSafeEqual } from 'node:crypto';

export const DPOP_NONCE_MAX_AGE_SECONDS = 300;

export function createDpopNonce(secret: string, now = Math.floor(Date.now() / 1000)): string {
	const timestamp = String(now);
	return `${timestamp}.${createHmac('sha256', secret).update(timestamp).digest('base64url')}`;
}

export function isValidDpopNonce(nonce: string, secret: string, now = Math.floor(Date.now() / 1000)): boolean {
	const [timestamp, signature] = nonce.split('.');
	const issuedAt = Number(timestamp);
	if (!Number.isInteger(issuedAt) || !signature || Math.abs(now - issuedAt) > DPOP_NONCE_MAX_AGE_SECONDS) {
		return false;
	}

	const expected = createHmac('sha256', secret).update(timestamp).digest('base64url');
	return signature.length === expected.length && timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}

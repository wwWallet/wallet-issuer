import { describe, expect, it } from 'vitest';
import { createDpopNonce, isValidDpopNonce } from './dpopNonce';

describe('DPoP nonce', () => {
	const secret = 'test-dpop-secret';
	const now = 1_700_000_000;

	it('creates a nonce that validates with the same secret', () => {
		const nonce = createDpopNonce(secret, now);

		expect(nonce).toMatch(/^1700000000\.[A-Za-z0-9_-]+$/);
		expect(isValidDpopNonce(nonce, secret, now)).toBe(true);
	});

	it('rejects a nonce signed with another secret', () => {
		const nonce = createDpopNonce(secret, now);

		expect(isValidDpopNonce(nonce, 'different-secret', now)).toBe(false);
	});

	it('rejects expired and malformed nonces', () => {
		const nonce = createDpopNonce(secret, now);

		expect(isValidDpopNonce(nonce, secret, now + 301)).toBe(false);
		expect(isValidDpopNonce('not-a-nonce', secret, now)).toBe(false);
		expect(isValidDpopNonce(`${now}.tampered`, secret, now)).toBe(false);
	});
});

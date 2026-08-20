import { createHash, randomUUID } from 'node:crypto';
import { calculateJwkThumbprint, exportJWK, generateKeyPair, JWK, SignJWT } from 'jose';
import { beforeEach, describe, expect, it } from 'vitest';
import { validateDpopProof } from './validateDpopProof';
import type { UniqueStore } from '../../../store/DataStore';
import { CredentialRequestErrors } from '../CredentialRequest/CredentialRequestError';

type SignKey = Parameters<SignJWT['sign']>[0];

describe('Function validateDpopProof', () => {
	const accessToken = 'test-access-token';
	const htu = 'https://issuer.example.test/credential';
	let replayStore: TestUniqueStore<string>;

	beforeEach(() => {
		replayStore = new TestUniqueStore<string>();
	});

	it('validates a bound DPoP proof for the credential endpoint', async () => {
		const proof = await createProof({ htu });

		const result = await validateDpopProof(proof.jwt, { jkt: proof.jkt }, {
			accessToken,
			htu,
			method: 'POST',
			replayStore,
		});

		expect(result).toEqual({ ok: true, value: null });
	});

	it('rejects a DPoP proof with the wrong endpoint URL', async () => {
		const proof = await createProof({ htu: 'https://issuer.example.test/other' });

		const result = await validateDpopProof(proof.jwt, { jkt: proof.jkt }, {
			accessToken,
			htu,
			method: 'POST',
			replayStore,
		});

		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error_description).toBe('DPoP proof htu mismatch');
		}
	});

	it('rejects a DPoP proof with the wrong method', async () => {
		const proof = await createProof({ htm: 'GET', htu });

		const result = await validateDpopProof(proof.jwt, { jkt: proof.jkt }, {
			accessToken,
			htu,
			method: 'POST',
			replayStore,
		});

		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error_description).toBe('DPoP proof htm mismatch');
		}
	});

	it('rejects a DPoP proof with the wrong access-token hash', async () => {
		const proof = await createProof({ accessToken: 'different-access-token', htu });

		const result = await validateDpopProof(proof.jwt, { jkt: proof.jkt }, {
			accessToken,
			htu,
			method: 'POST',
			replayStore,
		});

		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error_description).toBe('DPoP proof ath mismatch');
		}
	});

	it('rejects a DPoP proof not bound to the introspected access token', async () => {
		const proof = await createProof({ htu });

		const result = await validateDpopProof(proof.jwt, { jkt: 'different-thumbprint' }, {
			accessToken,
			htu,
			method: 'POST',
			replayStore,
		});

		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error_description).toContain('different JWK thumbprint');
		}
	});

	it('rejects stale DPoP proofs', async () => {
		const proof = await createProof({ htu, iat: Math.floor(Date.now() / 1000) - 400 });

		const result = await validateDpopProof(proof.jwt, { jkt: proof.jkt }, {
			accessToken,
			htu,
			method: 'POST',
			replayStore,
		});

		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error_description).toBe('DPoP proof iat is not recent enough');
		}
	});

	it('rejects replayed DPoP proofs', async () => {
		const proof = await createProof({ htu });
		const options = {
			accessToken,
			htu,
			method: 'POST',
			replayStore,
		};

		expect(await validateDpopProof(proof.jwt, { jkt: proof.jkt }, options)).toEqual({ ok: true, value: null });

		const result = await validateDpopProof(proof.jwt, { jkt: proof.jkt }, options);

		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error_description).toBe('DPoP proof replay detected');
		}
	});

	it('accepts exactly one of two concurrent uses of the same proof', async () => {
		const proof = await createProof({ htu });
		const options = {
			accessToken,
			htu,
			method: 'POST',
			replayStore,
		};

		const results = await Promise.all([
			validateDpopProof(proof.jwt, { jkt: proof.jkt }, options),
			validateDpopProof(proof.jwt, { jkt: proof.jkt }, options),
		]);

		expect(results.filter((result) => result.ok)).toHaveLength(1);
		expect(results.filter((result) => !result.ok)).toHaveLength(1);
		expect(results.find((result) => !result.ok)).toMatchObject({
			error_description: 'DPoP proof replay detected',
		});
	});

	it('stores a hashed replay identifier for the remaining proof lifetime', async () => {
		const proof = await createProof({ htu });

		await validateDpopProof(proof.jwt, { jkt: proof.jkt }, {
			accessToken,
			htu,
			method: 'POST',
			replayStore,
		});

		expect(replayStore.attempts).toHaveLength(1);
		expect(replayStore.attempts[0].key).toMatch(/^[A-Za-z0-9_-]{43}$/);
		expect(replayStore.attempts[0].ttlMs).toBeGreaterThan(299000);
		expect(replayStore.attempts[0].ttlMs).toBeLessThanOrEqual(301000);
	});

	it('fails closed when the replay store is unavailable', async () => {
		const proof = await createProof({ htu });
		const unavailableReplayStore: UniqueStore<string, string> = {
			setIfAbsent: async () => {
				throw new Error('Valkey unavailable');
			},
		};

		const result = await validateDpopProof(proof.jwt, { jkt: proof.jkt }, {
			accessToken,
			htu,
			method: 'POST',
			replayStore: unavailableReplayStore,
		});

		expect(result).toEqual({
			error: CredentialRequestErrors.InternalServerError,
			error_description: 'Could not check DPoP proof replay state',
			ok: false,
		});
	});
});

class TestUniqueStore<TValue> implements UniqueStore<string, TValue> {
	private readonly values = new Map<string, TValue>();
	readonly attempts: Array<{ key: string; ttlMs: number }> = [];

	async setIfAbsent(key: string, value: TValue, ttlMs: number): Promise<boolean> {
		this.attempts.push({ key, ttlMs });
		if (this.values.has(key)) {
			return false;
		}
		this.values.set(key, value);
		return true;
	}
}

async function createProof({
	accessToken = 'test-access-token',
	htm = 'POST',
	htu,
	iat = Math.floor(Date.now() / 1000),
}: {
	accessToken?: string;
	htm?: string;
	htu: string;
	iat?: number;
}): Promise<{ jwt: string; jkt: string }> {
	const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
	const publicJwk = await exportJWK(publicKey);
	const jwt = await signProof(privateKey, publicJwk, {
		ath: calculateAth(accessToken),
		htm,
		htu,
		iat,
		jti: randomUUID(),
	});

	return {
		jkt: await calculateJwkThumbprint(publicJwk),
		jwt,
	};
}

async function signProof(privateKey: SignKey, publicJwk: JWK, payload: {
	ath: string;
	htm: string;
	htu: string;
	iat: number;
	jti: string;
}): Promise<string> {
	return new SignJWT({
		ath: payload.ath,
		htm: payload.htm,
		htu: payload.htu,
		jti: payload.jti,
	})
		.setProtectedHeader({
			alg: 'ES256',
			typ: 'dpop+jwt',
			jwk: publicJwk,
		})
		.setIssuedAt(payload.iat)
		.sign(privateKey);
}

function calculateAth(token: string): string {
	return createHash('sha256')
		.update(token)
		.digest('base64url');
}

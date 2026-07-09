import { createHash, randomUUID } from 'node:crypto';
import { calculateJwkThumbprint, exportJWK, generateKeyPair, JWK, SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';
import { validateDpopProof } from './validateDpopProof';

type SignKey = Parameters<SignJWT['sign']>[0];

describe('Function validateDpopProof', () => {
	const accessToken = 'test-access-token';
	const htu = 'https://issuer.example.test/credential';

	it('validates a bound DPoP proof for the credential endpoint', async () => {
		const proof = await createProof({ htu });

		const result = await validateDpopProof(proof.jwt, { jkt: proof.jkt }, {
			accessToken,
			htu,
			method: 'POST',
		});

		expect(result).toEqual({ ok: true, value: null });
	});

	it('rejects a DPoP proof with the wrong endpoint URL', async () => {
		const proof = await createProof({ htu: 'https://issuer.example.test/other' });

		const result = await validateDpopProof(proof.jwt, { jkt: proof.jkt }, {
			accessToken,
			htu,
			method: 'POST',
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
		};

		expect(await validateDpopProof(proof.jwt, { jkt: proof.jkt }, options)).toEqual({ ok: true, value: null });

		const result = await validateDpopProof(proof.jwt, { jkt: proof.jkt }, options);

		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error_description).toBe('DPoP proof replay detected');
		}
	});
});

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

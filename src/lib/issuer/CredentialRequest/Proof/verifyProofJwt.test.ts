import { beforeAll, describe, expect, it, vi } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT, type JWK } from 'jose';
import { verifyProofJwt } from './verifyProofJwt';
import { verifyProofKeyAttestation } from './verifyProofKeyAttestation';
import type { VerifyProofOptions } from './verifyProof';

const trust = vi.hoisted(() => ({ publicKey: undefined as CryptoKey | undefined, trusted: true }));
// Isolate certificate resolution; all KA and holder signatures use real crypto.
vi.mock('wallet-common', async (original) => ({
	...await original<typeof import('wallet-common')>(),
	verifyX5C: vi.fn(async () => trust.trusted),
}));
vi.mock('jose', async (original) => ({
	...await original<typeof import('jose')>(),
	importX509: vi.fn(async () => trust.publicKey),
}));

const options: VerifyProofOptions = {
	getAllTrustedPemCertificates: async () => ['test trust anchor'],
	requiredVerificationMechanisms: ['x5c'],
	credentialIssuerIdentifier: 'https://issuer.example',
	expectedNonce: 'issuer-nonce',
};
let provider: Awaited<ReturnType<typeof generateKeyPair>>;
let holder: Awaited<ReturnType<typeof generateKeyPair>>;
let other: Awaited<ReturnType<typeof generateKeyPair>>;
let keys: JWK[];

beforeAll(async () => {
	[provider, holder, other] = await Promise.all([generateKeyPair('ES256'), generateKeyPair('ES256'), generateKeyPair('ES256')]);
	trust.publicKey = provider.publicKey;
	keys = await Promise.all([exportJWK(holder.publicKey), exportJWK(other.publicKey)]);
});

async function makeKa(attestedKeys = keys, expiration = '5m', signer = provider.privateKey) {
	return new SignJWT({ attested_keys: attestedKeys, nonce: options.expectedNonce })
		.setProtectedHeader({ alg: 'ES256', typ: 'key-attestation+jwt', x5c: ['dGVzdA=='] })
		.setIssuedAt().setExpirationTime(expiration).sign(signer);
}

async function makeProof(ka: string, settings: {
	signer?: CryptoKey; jwk?: JWK; audience?: string; nonce?: string; extraHeader?: Record<string, unknown>;
} = {}) {
	return new SignJWT({ nonce: settings.nonce ?? options.expectedNonce })
		.setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', key_attestation: ka,
			...(settings.jwk ? { jwk: settings.jwk } : {}), ...settings.extraHeader })
		.setAudience(settings.audience ?? options.credentialIssuerIdentifier).setIssuedAt()
		.sign(settings.signer ?? holder.privateKey);
}

describe('KA-bound JWT proof possession', () => {
	it.each([false, true])('accepts key-zero signature with matching header JWK present=%s', async (includeJwk) => {
		const result = await verifyProofJwt(await makeProof(await makeKa(), { jwk: includeJwk ? keys[0] : undefined }), options);
		expect(result).toEqual({ ok: true, value: { attested_keys: keys } });
	});
	it('verifies a KA with verification usage added to a sign-only exported public key', async () => {
		const keypair = await crypto.subtle.generateKey(
			{ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign'],
		);
		const exported = await crypto.subtle.exportKey('jwk', keypair.publicKey);
		expect(exported.key_ops).toEqual([]);
		const publicJwk: JWK = { ...exported, key_ops: ['verify'] };
		const proof = await makeProof(await makeKa([publicJwk]), {
			signer: keypair.privateKey, jwk: publicJwk,
		});
		expect((await verifyProofJwt(proof, options)).ok).toBe(true);
		expect(exported.key_ops).toEqual([]);
	});
	it.each([false, true])('rejects index-one signature with its header JWK present=%s', async (includeJwk) => {
		const proof = await makeProof(await makeKa(), { signer: other.privateKey, jwk: includeJwk ? keys[1] : undefined });
		expect((await verifyProofJwt(proof, options)).ok).toBe(false);
	});
	it('rejects a tampered outer signature without a header JWK', async () => {
		const proof = await makeProof(await makeKa());
		const parts = proof.split('.');
		parts[2] = Buffer.alloc(64).toString('base64url');
		expect((await verifyProofJwt(parts.join('.'), options)).ok).toBe(false);
	});
	it('rejects a conflicting JWK even when signed by key zero', async () => {
		expect((await verifyProofJwt(await makeProof(await makeKa(), { jwk: keys[1] }), options)).ok).toBe(false);
	});
	it.each([{ kid: 'different-key' }, { x5c: ['dGVzdA=='] }, { key_attestation: 123 }, { jwk: null }])('rejects conflicting or malformed headers %j', async (extraHeader) => {
		expect((await verifyProofJwt(await makeProof(await makeKa(), { extraHeader }), options)).ok).toBe(false);
	});
	it.each([{ audience: 'https://other.example' }, { nonce: 'wrong-nonce' }, { nonce: '' }])('rejects invalid proof claims %j', async (settings) => {
		expect((await verifyProofJwt(await makeProof(await makeKa(), settings), options)).ok).toBe(false);
	});
	it('rejects an expired KA', async () => {
		expect((await verifyProofJwt(await makeProof(await makeKa(keys, '-1m')), options)).ok).toBe(false);
	});
	it('rejects an incorrectly signed KA', async () => {
		expect((await verifyProofJwt(await makeProof(await makeKa(keys, '5m', other.privateKey)), options)).ok).toBe(false);
	});
	it('rejects an untrusted provider', async () => {
		trust.trusted = false;
		try {
			expect((await verifyProofJwt(await makeProof(await makeKa()), options)).ok).toBe(false);
		} finally { trust.trusted = true; }
	});
	it('rejects unsupported trust configuration', async () => {
		expect((await verifyProofJwt(await makeProof(await makeKa()), { ...options, requiredVerificationMechanisms: [] })).ok).toBe(false);
	});
	it('rejects empty attested_keys', async () => {
		expect((await verifyProofKeyAttestation(await makeKa([]), options)).ok).toBe(false);
	});
	it('preserves ordinary JWK proofs', async () => {
		const proof = await new SignJWT({ nonce: options.expectedNonce }).setIssuedAt()
			.setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: keys[0] }).sign(holder.privateKey);
		expect((await verifyProofJwt(proof, options)).ok).toBe(true);
	});
});

import { describe, expect, it, vi } from 'vitest';
import { verifyProofKeyAttestation } from './verifyProofKeyAttestation';
import { VerifyProofOptions } from './verifyProof';

function unsignedAttestation(payload: Record<string, unknown>): string {
	const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
	return `${encode({ typ: 'key-attestation+jwt', alg: 'ES256' })}.${encode(payload)}.`;
}

const baseOptions: VerifyProofOptions = {
	getAllTrustedPemCertificates: async () => [],
	requiredVerificationMechanisms: [],
	credentialIssuerIdentifier: 'https://issuer.example',
};

describe('verifyProofKeyAttestation nonce validation', () => {
	it('requires a nonce for a standalone attestation proof', async () => {
		const result = await verifyProofKeyAttestation(
			unsignedAttestation({ attested_keys: [{}] }),
			baseOptions,
			true,
		);

		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error).toBe('invalid_nonce');
		}
	});

	it('rejects a nonce that fails the issuer verifier', async () => {
		const verifyNonce = vi.fn().mockResolvedValue(false);
		const result = await verifyProofKeyAttestation(
			unsignedAttestation({ nonce: 'signed-nonce', attested_keys: [{}] }),
			{ ...baseOptions, verifyNonce },
			true,
		);

		expect(result.ok).toBe(false);
		expect(verifyNonce).toHaveBeenCalledWith('signed-nonce');
	});
});

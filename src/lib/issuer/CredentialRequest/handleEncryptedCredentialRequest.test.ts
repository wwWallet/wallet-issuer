import { beforeEach, describe, expect, it, vi } from 'vitest';
import { compactDecrypt, importJWK } from 'jose';
import { handleEncryptedCredentialRequest } from './handleEncryptedCredentialRequest';

vi.mock('jose', async () => {
	const actual = await vi.importActual<typeof import('jose')>('jose');
	return {
		...actual,
		compactDecrypt: vi.fn(),
		importJWK: vi.fn(),
	};
});

const metadata = {
	credential_request_encryption: {
		enc_values_supported: ['A256GCM'],
	},
} as any;

const encryption = {
	encryptionRequired: false,
	keypair: {
		alg: 'ECDH-ES',
		publicKeyJwk: { kid: 'issuer-key' },
		privateKeyJwk: { kid: 'issuer-key' },
	},
};

const plainData = {
	credential_configuration_id: 'example',
	proofs: { jwt: ['proof'] },
};

describe('handleEncryptedCredentialRequest', () => {
	beforeEach(() => {
		vi.clearAllMocks();
	});

	it('preserves the request shape for plain JSON requests', async () => {
		const request = {
			request: {
				headers: { 'content-type': 'application/json', authorization: 'Bearer token', dpop: 'proof' },
				data: plainData,
			},
		} as any;

		const result = await handleEncryptedCredentialRequest(metadata, request, encryption);

		expect(result).toEqual({ ok: true, value: request });
	});

	it('normalizes decrypted requests to the plain request shape', async () => {
		vi.mocked(importJWK).mockResolvedValue({} as CryptoKey);
		vi.mocked(compactDecrypt).mockResolvedValue({
			plaintext: new TextEncoder().encode(JSON.stringify(plainData)),
			protectedHeader: { enc: 'A256GCM' },
		} as any);

		const result = await handleEncryptedCredentialRequest(metadata, {
			request: {
				headers: { 'content-type': 'application/jwt', authorization: 'Bearer token', dpop: 'proof' },
				data: 'encrypted-request',
			},
		}, encryption);

		expect(result).toEqual({
			ok: true,
			value: {
				request: {
					headers: { 'content-type': 'application/json', authorization: 'Bearer token', dpop: 'proof' },
					data: plainData,
				},
			},
		});
	});

	it('returns an invalid request when decryption fails', async () => {
		vi.mocked(importJWK).mockResolvedValue({} as CryptoKey);
		vi.mocked(compactDecrypt).mockRejectedValue(new Error('bad JWE'));

		const result = await handleEncryptedCredentialRequest(metadata, {
			request: {
				headers: { 'content-type': 'application/jwt', authorization: 'Bearer token', dpop: 'proof' },
				data: 'invalid-request',
			},
		}, encryption);

		expect(result).toMatchObject({ ok: false, error: 'invalid_credential_request' });
	});
});

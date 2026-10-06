import express from 'express';
import { CompactEncrypt, exportJWK, generateKeyPair } from 'jose';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { handleEncryptedCredentialRequest } from '../lib/issuer/CredentialRequest/handleEncryptedCredentialRequest';

const { issuerMock } = vi.hoisted(() => ({ issuerMock: { issueCredential: vi.fn() } }));
vi.mock('./issuer', () => ({ issuer: issuerMock }));
vi.mock('fs', async (importOriginal) => { const actual = await importOriginal<typeof import('fs')>(); return { ...actual, default: { ...actual, readFileSync: () => '' }, readFileSync: () => '' }; });

describe('VCI credential endpoint request parsing', () => {
	afterEach(() => vi.clearAllMocks());
	it('passes an application/jwt request body to the issuer as text', async () => {
		issuerMock.issueCredential.mockResolvedValue({ status: 200, headers: { 'content-type': 'application/json' }, data: { credential: 'ok' } });
		const { vciRouter } = await import('./router');
		const app = express().use(vciRouter);
		const server = await new Promise<ReturnType<typeof app.listen>>((resolve) => resolve(app.listen(0)));
		try {
			const address = server.address();
			if (!address || typeof address === 'string') throw new Error('server did not bind');
			const response = await fetch('http://127.0.0.1:' + address.port + '/credential', { method: 'POST', headers: { 'content-type': 'application/jwt' }, body: 'encrypted-request' });
			expect(response.status).toBe(200);
			expect(issuerMock.issueCredential).toHaveBeenCalledWith({ request: { headers: expect.objectContaining({ 'content-type': 'application/jwt' }), data: 'encrypted-request' } });
		} finally {
			await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
		}
	});

	it.each([
		{ status: 202, data: { transaction_id: 'pending-transaction', interval: 60 } },
		{ status: 200, data: { credentials: [{ credential: 'issued-credential' }] } },
	])('decrypts an encrypted deferred poll and forwards the $status response', async ({ status, data }) => {
		const { publicKey, privateKey } = await generateKeyPair('ECDH-ES', { extractable: true });
		const encryption = {
			encryptionRequired: true,
			keypair: {
				alg: 'ECDH-ES',
				publicKeyJwk: await exportJWK(publicKey),
				privateKeyJwk: await exportJWK(privateKey),
			},
		};
		const poll = { transaction_id: 'pending-transaction' };
		const encryptedPoll = await new CompactEncrypt(new TextEncoder().encode(JSON.stringify(poll)))
			.setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
			.encrypt(publicKey);
		const decryptedRequest = vi.fn();
		issuerMock.issueCredential.mockImplementation(async (request) => {
			const result = await handleEncryptedCredentialRequest({
				credential_request_encryption: { enc_values_supported: ['A256GCM'] },
			} as any, request, encryption);
			if (!result.ok) {
				return { status: 400, headers: { 'content-type': 'application/json' }, data: { error: result.error } };
			}
			decryptedRequest(result.value);
			return { status, headers: { 'content-type': 'application/json' }, data };
		});
		const { vciRouter } = await import('./router');
		const server = express().use(vciRouter).listen(0);
		try {
			const address = server.address();
			if (!address || typeof address === 'string') throw new Error('server did not bind');
			const response = await fetch('http://127.0.0.1:' + address.port + '/deferred-credential', {
				method: 'POST',
				headers: { 'content-type': 'application/jwt', authorization: 'Bearer token', dpop: 'proof' },
				body: encryptedPoll,
			});
			expect(issuerMock.issueCredential).toHaveBeenCalledWith({ request: {
				headers: expect.objectContaining({ 'content-type': 'application/jwt', authorization: 'Bearer token', dpop: 'proof' }),
				data: encryptedPoll,
			} });
			expect(decryptedRequest).toHaveBeenCalledWith({ request: {
				headers: expect.objectContaining({ 'content-type': 'application/json', authorization: 'Bearer token', dpop: 'proof' }),
				data: poll,
			} });
			expect(response.status).toBe(status);
			expect(response.headers.get('content-type')).toContain('application/json');
			expect(await response.json()).toEqual(data);
		} finally {
			await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
		}
	});
});

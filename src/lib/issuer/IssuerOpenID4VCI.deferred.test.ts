import { beforeEach, describe, expect, it, vi } from 'vitest';
import { CompactEncrypt, compactDecrypt, exportJWK, generateKeyPair } from 'jose';
import { ok, VerifiableCredentialFormat } from 'wallet-common';
import { createIssuerOpenID4VCI, CredentialIssuerCreateOptions } from './IssuerOpenID4VCI';
import { validateAccessToken } from './AccessToken/validateAccessToken';
import { verifyProofsWrapper } from './CredentialRequest/Proof/verifyProof';
import { PlainIssueCredentialRequestOptionsData } from './IssuerOpenID4VCITypes';

vi.mock('../../store/dataStoreClient', () => ({ dataStoreClient: {} }));
vi.mock('./AccessToken/validateAccessToken', () => ({ validateAccessToken: vi.fn() }));
vi.mock('./CredentialRequest/Proof/verifyProof', () => ({ verifyProofsWrapper: vi.fn() }));

function memoryStore<T>() {
	const entries = new Map<string, T>();
	return {
		get: vi.fn(async (id: string) => entries.get(id)),
		set: vi.fn(async (id: string, value: T) => { entries.set(id, value); }),
	};
}

async function setup() {
	const issuerKeys = await generateKeyPair('ECDH-ES', { extractable: true });
	const walletKeys = await generateKeyPair('ECDH-ES', { extractable: true });
	const holderKeys = await generateKeyPair('ES256', { extractable: true });
	const holderJwk = await exportJWK(holderKeys.publicKey);
	const responseEncryption = { jwk: { ...await exportJWK(walletKeys.publicKey), alg: 'ECDH-ES' }, enc: 'A256GCM' };
	const claims = vi.fn()
		.mockResolvedValueOnce(ok({ status: 'pending', transaction_id: 'transaction' }))
		.mockResolvedValueOnce(ok({ status: 'pending', transaction_id: 'transaction' }))
		.mockResolvedValue(ok({ status: 'resolved', transaction_id: 'transaction', data: { claims: { given_name: 'Alice' } } }));
	const signSdJwtVc = vi.fn().mockResolvedValue({ credential: 'signed-credential' });
	const stateStore = memoryStore();
	const stateByTransactionIdStore = memoryStore<string>();
	vi.mocked(validateAccessToken).mockResolvedValue(ok({ sub: 'account', client_id: 'wallet', scope: 'example', active: true }));
	vi.mocked(verifyProofsWrapper).mockResolvedValue(ok({ attested_keys: [holderJwk] }));
	const issuer = createIssuerOpenID4VCI('https://issuer.example', {
		stateStore,
		stateByTransactionIdStore,
		credentialOfferStore: memoryStore(),
		preAuthorizedCodeStore: memoryStore(),
		secret: 'test-secret',
		clockTolerance: 60,
		credentialRequestEncryption: {
			encryptionRequired: true,
			keypair: {
				alg: 'ECDH-ES',
				publicKeyJwk: { ...await exportJWK(issuerKeys.publicKey), kid: 'issuer-key' },
				privateKeyJwk: await exportJWK(issuerKeys.privateKey),
			},
		},
		credentialResponseEncryption: { encryptionRequired: true },
		deferredCredentialResponseInterval: 30,
		requireKeyBindingInCredentialConfigurationIds: ['example'],
		findAccount: vi.fn().mockResolvedValue({ accountId: 'account', claims }),
		credentialSigner: { signSdJwtVc },
	} as unknown as CredentialIssuerCreateOptions);
	issuer.registerSupportedCredentialConfiguration('example', {
		format: VerifiableCredentialFormat.DC_SDJWT,
		scope: 'example',
		vct: 'https://issuer.example/example',
	});
	const request = async (data: PlainIssueCredentialRequestOptionsData) => {
		const jwe = await new CompactEncrypt(new TextEncoder().encode(JSON.stringify(data)))
			.setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
			.encrypt(issuerKeys.publicKey);
		return issuer.issueCredential({ request: {
			headers: { 'content-type': 'application/jwt', authorization: 'DPoP token', dpop: 'dpop-proof' },
			data: jwe,
		} });
	};
	return { issuer, walletKeys, holderJwk, responseEncryption, request, claims, signSdJwtVc, stateStore, stateByTransactionIdStore };
}

describe('encrypted deferred issuance', () => {
	beforeEach(() => vi.resetAllMocks());

	it('preserves pending statuses and completes encrypted polling with the stored holder key', async () => {
		const context = await setup();
		const decryptResponse = async (response: Awaited<ReturnType<typeof context.request>>) => {
			expect(response.headers['content-type']).toBe('application/jwt');
			expect(typeof response.data).toBe('string');
			const { plaintext } = await compactDecrypt(response.data as string, context.walletKeys.privateKey);
			return JSON.parse(new TextDecoder().decode(plaintext));
		};
		const initial = await context.request({ credential_configuration_id: 'example', proofs: { jwt: ['holder-proof'] }, credential_response_encryption: context.responseEncryption });
		expect(initial.status).toBe(202);
		const pending = await decryptResponse(initial);
		expect(pending).toEqual({ transaction_id: 'transaction', interval: 30 });
		expect(context.stateByTransactionIdStore.set).toHaveBeenCalledWith('transaction', expect.any(String));
		expect(context.signSdJwtVc).not.toHaveBeenCalled();

		const poll = { transaction_id: pending.transaction_id, credential_response_encryption: context.responseEncryption };
		const stillPending = await context.request(poll);
		expect(stillPending.status).toBe(202);
		expect(await decryptResponse(stillPending)).toEqual(pending);
		expect(context.signSdJwtVc).not.toHaveBeenCalled();

		const completed = await context.request(poll);
		expect(completed.status).toBe(200);
		expect(await decryptResponse(completed)).toEqual({ credentials: [{ credential: 'signed-credential' }] });
		expect(context.stateByTransactionIdStore.get).toHaveBeenCalledWith('transaction');
		expect(verifyProofsWrapper).toHaveBeenCalledTimes(1);
		expect(validateAccessToken).toHaveBeenCalledTimes(3);
		expect(context.signSdJwtVc).toHaveBeenCalledExactlyOnceWith({ given_name: 'Alice', cnf: { jwk: context.holderJwk } }, {}, {});
	});

	it('rejects an encrypted poll with an unknown transaction', async () => {
		const context = await setup();
		const response = await context.request({ transaction_id: 'unknown', credential_response_encryption: context.responseEncryption });
		expect(response.status).toBe(400);
		expect(response.data).toMatchObject({ error: 'invalid_credential_request' });
		expect(context.claims).not.toHaveBeenCalled();
		expect(context.signSdJwtVc).not.toHaveBeenCalled();
	});

	it('requires response encryption parameters on the poll even when the initial request supplied them', async () => {
		const context = await setup();
		await context.request({ credential_configuration_id: 'example', proofs: { jwt: ['holder-proof'] }, credential_response_encryption: context.responseEncryption });
		const response = await context.request({ transaction_id: 'transaction' });
		expect(response.status).toBe(400);
		expect(response.headers['content-type']).toBe('application/json');
		expect(response.data).toMatchObject({ error: 'invalid_encryption_parameters' });
		expect(context.signSdJwtVc).not.toHaveBeenCalled();
	});
});

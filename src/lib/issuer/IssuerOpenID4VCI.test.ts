import { beforeEach, describe, expect, it, vi } from 'vitest';
import { VerifiableCredentialFormat } from 'wallet-common';
import { createIssuerOpenID4VCI, retrieveCredentialOffer } from './IssuerOpenID4VCI';

describe('retrieveCredentialOffer', () => {
	const offer = {
		credential_issuer: 'https://issuer.example',
		credential_configuration_ids: ['pid'],
	};

	it('atomically consumes an offer when revocation is enabled', async () => {
		const store = {
			consume: vi.fn().mockResolvedValue(offer),
			get: vi.fn(),
		};

		await expect(retrieveCredentialOffer(store as any, 'offer-id', true)).resolves.toEqual(offer);
		expect(store.consume).toHaveBeenCalledWith('offer-id');
		expect(store.get).not.toHaveBeenCalled();
	});

	it('reads an offer without consuming it when revocation is disabled', async () => {
		const store = {
			consume: vi.fn(),
			get: vi.fn().mockResolvedValue(offer),
		};

		await expect(retrieveCredentialOffer(store as any, 'offer-id', false)).resolves.toEqual(offer);
		expect(store.get).toHaveBeenCalledWith('offer-id');
		expect(store.consume).not.toHaveBeenCalled();
	});

	it('returns null when an offer is missing or already consumed', async () => {
		const store = {
			consume: vi.fn().mockResolvedValue(undefined),
		};

		await expect(retrieveCredentialOffer(store as any, 'missing-offer', true)).resolves.toBeNull();
	});

	it('allows only one of two concurrent requests to consume an offer', async () => {
		const store = {
			consume: vi.fn()
				.mockResolvedValueOnce(offer)
				.mockResolvedValueOnce(undefined),
		};

		const results = await Promise.all([
			retrieveCredentialOffer(store as any, 'single-use-offer', true),
			retrieveCredentialOffer(store as any, 'single-use-offer', true),
		]);

		expect(results).toEqual(expect.arrayContaining([offer, null]));
		expect(store.consume).toHaveBeenCalledTimes(2);
		expect(store.consume).toHaveBeenNthCalledWith(1, 'single-use-offer');
		expect(store.consume).toHaveBeenNthCalledWith(2, 'single-use-offer');
	});
});

describe('generateCredentialOffer', () => {
	let storedOffers: Map<string, any>;
	let issuer: ReturnType<typeof createIssuerOpenID4VCI>;

	beforeEach(() => {
		storedOffers = new Map();
		const genericStore = () => ({
			get: vi.fn(),
			set: vi.fn(),
			consume: vi.fn(),
		});
		const credentialOfferStore = {
			get: vi.fn(async (id: string) => storedOffers.get(id)),
			set: vi.fn(async (id: string, offer: unknown) => { storedOffers.set(id, offer); }),
			consume: vi.fn(),
		};
		issuer = createIssuerOpenID4VCI('https://issuer.example', {
			authorizationServerUrl: 'https://as.example',
			stateStore: genericStore() as any,
			stateByTransactionIdStore: genericStore() as any,
			credentialOfferStore: credentialOfferStore as any,
			preAuthorizedCodeStore: genericStore() as any,
			secret: 'test-secret',
			credentialRequestHelper: {} as any,
			clockTolerance: 0,
			getAllTrustedPemCertificates: async () => [],
			findAccount: vi.fn(),
			credentialSigner: {} as any,
			proofTypesSupported: [],
			requireKeyBindingInCredentialConfigurationIds: [],
			x5c: [],
			introspectionEndpointBasicAuthString: '',
		});
		issuer.registerSupportedCredentialConfiguration('pid_sd_jwt', {
			format: VerifiableCredentialFormat.DC_SDJWT,
			scope: 'pid:sd_jwt_dc',
			vct: 'urn:eudi:pid:1',
		} as any);
		issuer.registerSupportedCredentialConfiguration('pid_mso_mdoc', {
			format: VerifiableCredentialFormat.MSO_MDOC,
			scope: 'pid:mso_mdoc',
			doctype: 'eu.europa.ec.eudi.pid.1',
		} as any);
	});

	it('keeps the singular caller compatible and emits an array', async () => {
		const result = await issuer.generateCredentialOffer({ credentialConfigurationId: 'pid_sd_jwt' });

		await expect(issuer.getCredentialOffer(result.credentialOfferId, false)).resolves.toMatchObject({
			credential_configuration_ids: ['pid_sd_jwt'],
		});
	});

	it('emits one mixed-format offer with both configuration ids', async () => {
		const result = await issuer.generateCredentialOffer({
			credentialConfigurationIds: ['pid_sd_jwt', 'pid_mso_mdoc'],
		});

		await expect(issuer.getCredentialOffer(result.credentialOfferId, false)).resolves.toMatchObject({
			credential_issuer: 'https://issuer.example',
			credential_configuration_ids: ['pid_sd_jwt', 'pid_mso_mdoc'],
		});
		expect(storedOffers).toHaveLength(1);
	});

	it('rejects unknown credential configuration ids', async () => {
		await expect(issuer.generateCredentialOffer({
			credentialConfigurationIds: ['pid_sd_jwt', 'unknown'],
		})).rejects.toThrow('Unsupported credential configuration id(s): unknown');
		expect(storedOffers).toHaveLength(0);
	});
});

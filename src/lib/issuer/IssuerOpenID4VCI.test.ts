import { describe, expect, it, vi } from 'vitest';
import { retrieveCredentialOffer } from './IssuerOpenID4VCI';

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
});

import { describe, expect, it } from 'vitest';
import { GenericStore } from 'wallet-common';
import { createCredentialRequestHelper, CredentialRequestWithClaims } from './CredentialRequestHelper';

class NoGetAllStore<TValue> implements GenericStore<string, TValue> {
	private readonly values = new Map<string, TValue>();

	async get(key: string): Promise<TValue | undefined> {
		return this.values.get(key);
	}

	async set(key: string, value: TValue): Promise<void> {
		this.values.set(key, value);
	}

	async getAll(): Promise<TValue[]> {
		throw new Error('getAll should not be called');
	}

	async delete(key: string): Promise<void> {
		this.values.delete(key);
	}
}

describe('CredentialRequestHelper', () => {
	it('uses the transaction id index when listing credential requests', async () => {
		const requestStore = new NoGetAllStore<CredentialRequestWithClaims>();
		const transactionIdIndexStore = new NoGetAllStore<string[]>();
		const helper = createCredentialRequestHelper(requestStore, transactionIdIndexStore);

		const pendingRequest = await helper.submitCredentialRequest({ sub: 'alice', scope: 'por:sd_jwt_vc' });
		const requests = await helper.getCredentialRequests();

		expect(requests).toEqual([pendingRequest]);
	});

	it('resolves individual credential requests directly by transaction id', async () => {
		const requestStore = new NoGetAllStore<CredentialRequestWithClaims>();
		const transactionIdIndexStore = new NoGetAllStore<string[]>();
		const helper = createCredentialRequestHelper(requestStore, transactionIdIndexStore);
		const pendingRequest = await helper.submitCredentialRequest({ sub: 'alice', scope: 'por:sd_jwt_vc' });

		await helper.fulfilCredentialRequest(pendingRequest.transaction_id, { sub: 'alice', family_name: 'Doe' });

		await expect(helper.getCredentialRequests(pendingRequest.transaction_id)).resolves.toEqual([
			{
				sub: 'alice',
				scope: 'por:sd_jwt_vc',
				status: 'resolved',
				data: { claims: { sub: 'alice', family_name: 'Doe' } },
				transaction_id: pendingRequest.transaction_id,
			},
		]);
	});
});

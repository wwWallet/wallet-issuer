import { describe, expect, it } from 'vitest';
import { GenericStore } from 'wallet-common';
import { createCredentialRequestHelper, CredentialRequestWithClaims } from './CredentialRequestHelper';
import { SetStore } from '../../store/DataStore';

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

class TestSetStore<TValue> implements SetStore<TValue> {
	private readonly values = new Map<string, Set<TValue>>();

	async addToSet(key: string, value: TValue): Promise<void> {
		const members = this.values.get(key) ?? new Set<TValue>();
		members.add(value);
		this.values.set(key, members);
	}

	async getSetMembers(key: string): Promise<TValue[]> {
		return [...(this.values.get(key) ?? [])];
	}

	async removeFromSet(key: string, value: TValue): Promise<void> {
		this.values.get(key)?.delete(value);
	}
}

describe('CredentialRequestHelper', () => {
	it('uses the transaction id index when listing credential requests', async () => {
		const requestStore = new NoGetAllStore<CredentialRequestWithClaims>();
		const transactionIdIndexStore = new TestSetStore<string>();
		const helper = createCredentialRequestHelper(requestStore, transactionIdIndexStore);

		const pendingRequest = await helper.submitCredentialRequest({ sub: 'alice', scope: 'por:sd_jwt_vc' });
		const requests = await helper.getCredentialRequests();

		expect(requests).toEqual([pendingRequest]);
	});

	it('resolves individual credential requests directly by transaction id', async () => {
		const requestStore = new NoGetAllStore<CredentialRequestWithClaims>();
		const transactionIdIndexStore = new TestSetStore<string>();
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

	it('does not lose transaction ids from concurrent submissions', async () => {
		const requestStore = new NoGetAllStore<CredentialRequestWithClaims>();
		const transactionIdIndexStore = new TestSetStore<string>();
		const helper = createCredentialRequestHelper(requestStore, transactionIdIndexStore);

		const pendingRequests = await Promise.all([
			helper.submitCredentialRequest({ sub: 'alice', scope: 'por:sd_jwt_vc' }),
			helper.submitCredentialRequest({ sub: 'bob', scope: 'por:sd_jwt_vc' }),
		]);

		const requests = await helper.getCredentialRequests();
		expect(requests).toHaveLength(2);
		expect(requests).toEqual(expect.arrayContaining(pendingRequests));
	});
});

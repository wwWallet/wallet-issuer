import { GenericStore } from 'wallet-common';
import { generateRandomIdentifier } from 'wallet-common';
import { ClaimsFuture } from './ClaimsFuture';
import { SetStore } from '../../store/DataStore';

type CredentialRequest = {
	transaction_id: string;
	sub: string;
	scope: string; // all scopes separated by space character
};

export type GenericClaims = {
	sub: string;
	[key: string]: unknown;
};

type CredentialRequestWithoutTransactionId = Omit<CredentialRequest, 'transaction_id'>;

export interface CredentialRequestHelper {
	submitCredentialRequest(request: CredentialRequestWithoutTransactionId): Promise<ClaimsFuture<GenericClaims>>;
	fulfilCredentialRequest(transaction_id: string, claims: GenericClaims): Promise<void>;
	getCredentialRequests(transaction_id?: string): Promise<ClaimsFuture<GenericClaims>[]>;
}

export type CredentialRequestWithClaims = CredentialRequest & { claims: GenericClaims; status: 'resolved' | 'rejected' | 'pending' };

const credentialRequestIndexKey = 'transaction_ids';

function toClaimsFuture(transaction: CredentialRequestWithClaims): ClaimsFuture<GenericClaims> {
	if (transaction.status === 'resolved') {
		return {
			scope: transaction.scope,
			sub: transaction.sub,
			status: transaction.status,
			data: { claims: transaction.claims },
			transaction_id: transaction.transaction_id,
		};
	}
	return {
		scope: transaction.scope,
		sub: transaction.sub,
		status: transaction.status,
		data: null,
		transaction_id: transaction.transaction_id,
	};
}

export function createCredentialRequestHelper(store: GenericStore<string, CredentialRequestWithClaims>, transactionIdIndexStore: SetStore<string>): CredentialRequestHelper {
	return {
		submitCredentialRequest: async (request) => {
			const transaction_id = generateRandomIdentifier(12);
			await store.set(transaction_id, { ...request, transaction_id, status: 'pending', claims: {} as GenericClaims });
			await transactionIdIndexStore.addToSet(credentialRequestIndexKey, transaction_id);
			return {
				sub: request.sub,
				scope: request.scope,
				status: 'pending',
				data: null,
				transaction_id: transaction_id,
			};
		},

		fulfilCredentialRequest: async (transaction_id, claims) => {
			const transaction = await store.get(transaction_id);
			if (!transaction) {
				return;
			}
			transaction.claims = { ...claims };
			transaction.status = 'resolved';

			await store.set(transaction_id, { ...transaction });
		},

		getCredentialRequests: async (transaction_id?: string) => {
			if (!transaction_id) {
				const transactionIds = await transactionIdIndexStore.getSetMembers(credentialRequestIndexKey);
				const transactions = await Promise.all(transactionIds.map((id) => store.get(id)));
				return transactions.filter((transaction) => transaction !== undefined).map(toClaimsFuture);
			}
			const transaction = await store.get(transaction_id);
			if (!transaction) {
				return [];
			}

			return [toClaimsFuture(transaction)];
		},
	};
}

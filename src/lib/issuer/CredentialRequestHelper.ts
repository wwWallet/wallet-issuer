import { GenericStore } from "../core/Store";
import { generateRandomIdentifier } from "../core/generateRandomIdentifier";


type PendingClaims = {
	sub: string;
	scope: string; // all scopes separated by space character
	transaction_id: string;
	status: 'pending';
	data: null;
};

type RejectedClaims = {
	sub: string;
	scope: string; // all scopes separated by space character
	transaction_id: string;
	status: 'rejected';
	data: null;
};

export type ResolvedClaims<Claims> = {
	sub: string;
	scope: string; // all scopes separated by space character
	transaction_id: string;
	status: 'resolved';
	data: {
		claims: Claims;
	};
};

export type ClaimsFuture<Claims> =
	| PendingClaims
	| RejectedClaims
	| ResolvedClaims<Claims>;

export function createClaimsFuture<Claims>(sub: string, scope: string, data?: { claims: Claims }): ClaimsFuture<Claims> {
	const transaction_id = generateRandomIdentifier(12);
	return data !== undefined ? {
		scope,
		sub,
		transaction_id: transaction_id,
		status: 'resolved',
		data: data,
	} : {
		scope,
		sub,
		transaction_id: transaction_id,
		status: 'pending',
		data: null,
	};
}

type CredentialRequest = {
	transaction_id: string;
	sub: string;
	scope: string; // all scopes separated by space character
}

export type GenericClaims = {
	sub: string;
	[key: string]: unknown;
}

type CredentialRequestWithoutTransactionId = Omit<CredentialRequest, "transaction_id">;

export interface CredentialRequestHelper {
	submitCredentialRequest(request: CredentialRequestWithoutTransactionId): Promise<ClaimsFuture<GenericClaims>>;
	fulfilCredentialRequest(transaction_id: string, claims: GenericClaims): Promise<void>;
	getCredentialRequests(transaction_id?: string): Promise<ClaimsFuture<GenericClaims>[]>;
}



export type CredentialRequestWithClaims = CredentialRequest & { claims: GenericClaims; status: 'resolved' | 'rejected' | 'pending' };


export function createCredentialRequestHelper(store: GenericStore<string, CredentialRequestWithClaims>): CredentialRequestHelper {
	
	return {
		submitCredentialRequest: async (request) => {
			
			const transaction_id = generateRandomIdentifier(12);
			await store.set(transaction_id, { ...request, transaction_id, status: 'pending', claims: {} as GenericClaims });
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
				const transactions = await store.getAll();
				return transactions.map((t) => {
					if (t.status === 'resolved') {
						return {
							scope: t.scope,
							sub: t.sub,
							status: t.status,
							data: { claims: t.claims },
							transaction_id: t.transaction_id,
						} satisfies ClaimsFuture<GenericClaims>;
					}
					return {
						scope: t.scope,
						sub: t.sub,
						status: t.status,
						data: null,
						transaction_id: t.transaction_id,
					} satisfies ClaimsFuture<GenericClaims>;
				});
			}
			const transaction = await store.get(transaction_id);
			if (!transaction) {
				return [];
			}

			if (transaction.status === 'resolved') {
				return [{
					scope: transaction.scope,
					sub: transaction.sub,
					status: 'resolved',
					data: {
						claims: transaction.claims,
					},
					transaction_id: transaction_id,
				}] satisfies ClaimsFuture<GenericClaims>[];
			}
			return [{
				scope: transaction.scope,
				sub: transaction.sub,
				status: transaction.status,
				transaction_id: transaction_id,
				data: null,
			}] satisfies ClaimsFuture<GenericClaims>[];
		},

	}
}
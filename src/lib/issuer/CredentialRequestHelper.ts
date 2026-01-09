import { GenericStore } from "../core/Store";
import { generateRandomIdentifier } from "../core/generateRandomIdentifier";


type PendingClaims = {
	transaction_id: string;
	status: 'pending';
	data: null;
};

type RejectedClaims = {
	transaction_id: string;
	status: 'rejected';
	data: null;
};

export type ResolvedClaims<Claims> = {
	transaction_id: string;
	status: 'resolved';
	data: {
		claims: Claims;
	}
};

export type ClaimsFuture<Claims> =
	| PendingClaims
	| RejectedClaims
	| ResolvedClaims<Claims>;

export function createClaimsFuture<Claims>(data?: { claims: Claims }): ClaimsFuture<Claims> {
	const transaction_id = generateRandomIdentifier(12);
	return data !== undefined ? {
		transaction_id: transaction_id,
		status: 'resolved',
		data: data,
	} : {
		transaction_id: transaction_id,
		status: 'pending',
		data: null,
	};
}

type CredentialRequest = {
	sub: string;
	scope: string; // all scopes separated by space character
}

export type GenericClaims = {
	sub: string;
	[key: string]: unknown;
}

export interface CredentialRequestHelper {
	submitCredentialRequest(request: CredentialRequest): Promise<ClaimsFuture<GenericClaims>>;
	fulfilCredentialRequest(transaction_id: string, claims: GenericClaims): Promise<void>;
	getCredentialRequest(transaction_id: string): Promise<ClaimsFuture<GenericClaims> | null>;
}



export type CredentialRequestWithClaims = CredentialRequest & { claims: GenericClaims; status: 'resolved' | 'rejected' | 'pending' };


export function createCredentialRequestHelper(store: GenericStore<string, CredentialRequestWithClaims>): CredentialRequestHelper {
	
	return {
		submitCredentialRequest: async (request) => {
			
			const transaction_id = generateRandomIdentifier(12);
			await store.set(transaction_id, { ...request, status: 'pending', claims: {} as GenericClaims });
			return {
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

		getCredentialRequest: async (transaction_id) => {
			const transaction = await store.get(transaction_id);
			if (!transaction) {
				return null;
			}

			if (transaction.status === 'resolved') {
				return {
					status: 'resolved',
					data: {
						claims: transaction.claims,
					},
					transaction_id: transaction_id,
				} satisfies ClaimsFuture<GenericClaims>;
			}
			return {
				status: transaction.status,
				transaction_id: transaction_id,
				data: null,
			} satisfies ClaimsFuture<GenericClaims>;
		},

	}
}
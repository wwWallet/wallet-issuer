import { generateRandomIdentifier } from "wallet-common";

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

export type ClaimsFuture<Claims> = PendingClaims | RejectedClaims | ResolvedClaims<Claims>;

export function createClaimsFuture<Claims>(sub: string, scope: string, data?: { claims: Claims }): ClaimsFuture<Claims> {
	const transaction_id = generateRandomIdentifier(12);
	return data !== undefined
		? {
				scope,
				sub,
				transaction_id: transaction_id,
				status: 'resolved',
				data: data,
			}
		: {
				scope,
				sub,
				transaction_id: transaction_id,
				status: 'pending',
				data: null,
			};
}

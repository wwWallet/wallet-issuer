import { ClaimsFuture, GenericClaims } from '../CredentialRequestHelper';

export interface Account {
	accountId: string;

	/**
	 *
	 * @param use
	 * @param scope Scopes requested
	 * @param claims Explicit claims requested via claims parameter
	 * @returns The return value will be the exact payload of the credential
	 */
	claims: (use: string, scope: string, claims?: Record<string, unknown>) => Promise<ClaimsFuture<GenericClaims>>;
}

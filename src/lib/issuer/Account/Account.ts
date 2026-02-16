import { Result } from 'wallet-common';
import { ClaimsFuture, GenericClaims } from '../CredentialRequestHelper';
import { CredentialRequestError } from '../CredentialRequest/CredentialRequestError';


export interface Account {
	accountId: string;

	/**
	 *
	 * @param use
	 * @param scope Scopes requested
	 * @param claims Explicit claims requested via claims parameter
	 * @returns The return value will be the exact payload of the credential
	 */
	claims: (use: string, scope: string, claims?: Record<string, unknown>) => Promise<Result<ClaimsFuture<GenericClaims>, CredentialRequestError>>;
}

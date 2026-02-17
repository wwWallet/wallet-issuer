import { Result } from 'wallet-common';
import { CredentialRequestError } from '../CredentialRequest/CredentialRequestError';
import { ClaimsFuture } from '../ClaimsFuture';
import { GenericClaims } from '../CredentialRequestHelper';

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

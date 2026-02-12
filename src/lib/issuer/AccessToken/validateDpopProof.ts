import { ok, err, Result, fromBase64Url } from 'wallet-common';
import { CredentialRequestError, CredentialRequestErrors } from '../CredentialRequest/CredentialRequestError';
import { calculateJwkThumbprint, JWK } from 'jose';

/**
 *
 * @param _dpopJwt
 * @param cnf The object returned from the introspection endpoint
 * @returns
 */
export async function validateDpopProof(dpopJwt: string, cnf?: { jkt?: string }): Promise<Result<null, CredentialRequestError>> {
	// RFC9449 - 6.2. JWK Thumbprint Confirmation Method in Token Introspection
	// https://datatracker.ietf.org/doc/html/rfc9449#section-6.2

	if (!cnf?.jkt) {
		return ok(null);
	}
	const decoder = new TextDecoder();

	const [encodedHeader, ,] = dpopJwt.split('.');

	const decodedHeader = JSON.parse(decoder.decode(fromBase64Url(encodedHeader))) as { alg: string; typ: 'dpop+jwt'; jwk: JWK };
	const calculatedJkt = await calculateJwkThumbprint(decodedHeader.jwk);
	if (calculatedJkt !== cnf.jkt) {
		return err(CredentialRequestErrors.InvalidRequest, 'DPoP binded public key has different JWK Thumbrint with the cnf.jkt received from the authorization server');
	}
	return ok(null);
}

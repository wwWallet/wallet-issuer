import { err, Result } from "../../core/Result";
import { CredentialRequestError, CredentialRequestErrors } from "../CredentialRequest/CredentialRequestError";

/**
 * 
 * @param _dpopJwt 
 * @param cnf The object returned from the introspection endpoint
 * @returns
 */
export async function validateDpopProof(_dpopJwt: string, _cnf?: { jkt?: string }): Promise<Result<{}, CredentialRequestError>> {
	// RFC9449 - 6.2. JWK Thumbprint Confirmation Method in Token Introspection
	// https://datatracker.ietf.org/doc/html/rfc9449#section-6.2

	return err(CredentialRequestErrors.InternalServerError, "DPoP proof currently not supported");
}

import { err, ok, Result } from "wallet-common";
import { CredentialRequestError, CredentialRequestErrors } from "./CredentialRequestError";
import { OpenidCredentialIssuerMetadata } from "wallet-common";
import { CompactEncrypt, importJWK } from "jose";
import { IssueCredentialResponse, PlainIssueCredentialRequestOptions, PlainIssueCredentialResponse } from "../IssuerOpenID4VCITypes";
import { CredentialIssuerCreateOptions } from "../IssuerOpenID4VCI";

export async function sendCredentialResponse(
	metadata: OpenidCredentialIssuerMetadata,
	requestOpts: PlainIssueCredentialRequestOptions,
	responseOpts: PlainIssueCredentialResponse,
	createOpts: CredentialIssuerCreateOptions
): Promise<Result<IssueCredentialResponse, CredentialRequestError>> {

	const encoder = new TextEncoder();

	if (createOpts.credentialResponseEncryption?.encryptionRequired &&
		requestOpts.request.data.credential_response_encryption === undefined) {

		return err(CredentialRequestErrors.InvalidEncryptionParameters, "Encryption params not received");
	}
	
	const encParamIsSupported = metadata.credential_response_encryption?.enc_values_supported.includes(requestOpts.request.data.credential_response_encryption?.enc as string) ?? false;
	if (requestOpts.request.data.credential_response_encryption && !encParamIsSupported) {
		return err(CredentialRequestErrors.InvalidEncryptionParameters, "Received not supported 'enc' credential_response_encryption value");
	}

	if (requestOpts.request.data.credential_response_encryption && encParamIsSupported && metadata.credential_response_encryption) {
		const { jwk, enc } = requestOpts.request.data.credential_response_encryption;
		const clientPublicKey = await importJWK(jwk, jwk.alg)
		const jwe = await new CompactEncrypt(encoder.encode(JSON.stringify(responseOpts.data)))
			.setProtectedHeader({
				enc: enc,
				alg: metadata.credential_response_encryption.alg_values_supported[0],
			})
			.encrypt(clientPublicKey);
		return ok({
			headers: { 'content-type': 'application/jwt' },
			data: jwe,
			status: 200,
		});
	}
	return ok(responseOpts);
}

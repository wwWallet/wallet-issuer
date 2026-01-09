import { err, ok, Result } from "../../core/Result";
import { IssueCredentialRequestOptions, PlainIssueCredentialRequestOptions } from "../IssuerOpenID4VCITypes";
import { CredentialRequestError, CredentialRequestErrors } from "./CredentialRequestError";
import { compactDecrypt, importJWK, JWK } from "jose";
import { OpenidCredentialIssuerMetadata } from "wallet-common";


/**
 * This function handles encrypted credential requests
 */
export async function handleEncryptedCredentialRequest(
	metadata: OpenidCredentialIssuerMetadata,
	requestOpts: IssueCredentialRequestOptions,
	credentialRequestEncryption?: {
	    encryptionRequired: boolean;
		keypair: {
			alg: string;
			publicKeyJwk: JWK;
			privateKeyJwk: JWK;
		},
	}): Promise<Result<PlainIssueCredentialRequestOptions, CredentialRequestError>> {


	const decoder = new TextDecoder();
	if (requestOpts.request.headers["Content-Type"] === 'application/jwt' &&
		typeof requestOpts.request.data === 'string') {

		if (!credentialRequestEncryption) {
			return err(CredentialRequestErrors.InvalidRequest, "Endpoint does not support request encryption");
		}

		try {
			const importedPrivateKey = await importJWK(
				credentialRequestEncryption.keypair.privateKeyJwk,
				credentialRequestEncryption.keypair.alg
			);
			const { plaintext, protectedHeader } = await compactDecrypt(requestOpts.request.data, importedPrivateKey);
			if ( metadata.credential_request_encryption &&
				!metadata.credential_request_encryption.enc_values_supported.includes(protectedHeader.enc)) {

				return err(CredentialRequestErrors.InvalidRequest, "'enc' value not supported");
			}
			const data = JSON.parse(decoder.decode(plaintext)) as PlainIssueCredentialRequestOptions;
			return ok(data);
		}
		catch {
			return err(CredentialRequestErrors.InvalidRequest, "Request decryption failed");
		}

	}
	else if (requestOpts.request.headers["Content-Type"] === 'application/jwt' ||
		typeof requestOpts.request.data === 'string') {

		return err(CredentialRequestErrors.InvalidRequest, "Invalid header or request body");
	}
	else if (credentialRequestEncryption &&
		credentialRequestEncryption.encryptionRequired) {
		return err(CredentialRequestErrors.InvalidRequest, "Request is expected to be encrypted");
	}
	else if (requestOpts.request.headers["Content-Type"] === 'application/json' &&
		typeof requestOpts.request.data === 'object') {

		return ok(requestOpts as PlainIssueCredentialRequestOptions);
	}

	return err(CredentialRequestErrors.InvalidRequest, "Could not parse the request");
}

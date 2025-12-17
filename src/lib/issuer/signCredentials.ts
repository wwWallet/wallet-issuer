import { OpenidCredentialIssuerMetadata } from "wallet-common";
import { CredentialIssuerCreateOptions } from "./createIssuerOpenID4VCI";
import { PlainIssueCredentialRequestOptions } from "./IssuerOpenID4VCI";
import { err, ok, Result } from "../core/Result";
import { CredentialRequestError, CredentialRequestErrors } from "./CredentialRequest/CredentialRequestError";
import { VerifiableCredentialFormat } from "wallet-common/dist/types";
import { JWK } from "jose";

export async function signCredentials(
		metadata: OpenidCredentialIssuerMetadata,
		claims: Record<string, unknown>,
		attestedKeys: JWK[],
		requestOpts: PlainIssueCredentialRequestOptions,
		createOpts: CredentialIssuerCreateOptions,
	): Promise<Result<string[], CredentialRequestError>> {

	const configurationId = requestOpts.request.data.credential_configuration_id;
	if (!configurationId) {
		return err(CredentialRequestErrors.InternalServerError, "'credential_configuration_id' is undefined");
	}

	const credentialConfigurationSupported = metadata.credential_configurations_supported[configurationId];
	if (!credentialConfigurationSupported) {
		return err(CredentialRequestErrors.InternalServerError, `Credential Configuration supported for id '${configurationId}' could not be resolved`);
	}

	// add error handling for signature generation
	switch (credentialConfigurationSupported.format) {
		case VerifiableCredentialFormat.DC_SDJWT:
			if (requestOpts.request.data.proofs) {
				const signedCredentials = await Promise.all(attestedKeys.map((key) =>
					// todo: dynamically generate disclosure frame based on metadata parameter
					createOpts.credentialSigner.signSdJwtVc({ ...claims, cnf: { jwk: key } }, {}, {})
				));
				return ok(signedCredentials.map((c) => c.credential));
			}
			else {
				const { credential } = await createOpts.credentialSigner.signSdJwtVc({ ...claims }, {}, {});
				return ok([credential]);
			}
		case VerifiableCredentialFormat.MSO_MDOC:
			if (requestOpts.request.data.proofs) {
				const signedCredentials = await Promise.all(attestedKeys.map((key) =>
					createOpts.credentialSigner.signMsoMdoc(
						credentialConfigurationSupported.doctype,
						new Map([
							['eu.europa.ec.eudi.pid.1', claims]
						]),
						key
					)
				));
				return ok(signedCredentials.map((c) => c.credential));
			}
			else {
				return err(CredentialRequestErrors.CredentialRequestDenied, "Cannot issue mso_mdoc credential without key-binding");
			}
		default:
			return err(CredentialRequestErrors.CredentialRequestDenied, "Unsupported credential format");
	}
}

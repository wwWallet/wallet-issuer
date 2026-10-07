import { err, ok, Result, OpenidCredentialIssuerMetadata, VerifiableCredentialFormat } from 'wallet-common';
import { CredentialRequestError, CredentialRequestErrors } from './CredentialRequest/CredentialRequestError';
import { JWK } from 'jose';
import { PlainIssueCredentialRequestOptions } from './IssuerOpenID4VCITypes';
import { CredentialIssuerCreateOptions } from './IssuerOpenID4VCI';
import { GenericClaims } from './CredentialRequestHelper';

export async function signCredentials(credentialConfigurationId: string, metadata: OpenidCredentialIssuerMetadata, claims: GenericClaims, attestedKeys: JWK[], disclosureFrameMap: Map<string, Record<string, unknown>>, _requestOpts: PlainIssueCredentialRequestOptions, createOpts: CredentialIssuerCreateOptions): Promise<Result<string[], CredentialRequestError>> {
	const credentialConfigurationSupported = metadata.credential_configurations_supported[credentialConfigurationId];
	if (!credentialConfigurationSupported) {
		return err(CredentialRequestErrors.InternalServerError, `Credential Configuration supported for id '${credentialConfigurationId}' could not be resolved`);
	}

	// add error handling for signature generation
	switch (credentialConfigurationSupported.format) {
		case VerifiableCredentialFormat.DC_SDJWT:
			if (attestedKeys.length) {
				const disclosureFrame = disclosureFrameMap.get(credentialConfigurationId);
				const signedCredentials = await Promise.all(attestedKeys.map((key) => createOpts.credentialSigner.signSdJwtVc({ ...claims, cnf: { jwk: key } }, {}, disclosureFrame ?? {})));
				return ok(signedCredentials.map((c) => c.credential));
			} else {
				return err(CredentialRequestErrors.InvalidProof, 'Cannot issue a key-bound dc+sd-jwt credential without a verified holder key');
			}
		case VerifiableCredentialFormat.MSO_MDOC:
			if (attestedKeys.length) {
				const { sub: _sub, ...claimsToBeSigned } = claims;
				const signedCredentials = await Promise.all(attestedKeys.map((key) => createOpts.credentialSigner.signMsoMdoc(credentialConfigurationSupported.doctype, new Map([[credentialConfigurationSupported.doctype, claimsToBeSigned]]), key)));
				return ok(signedCredentials.map((c) => c.credential));
			} else {
				return err(CredentialRequestErrors.CredentialRequestDenied, 'Cannot issue mso_mdoc credential without key-binding');
			}
		default:
			return err(CredentialRequestErrors.CredentialRequestDenied, 'Unsupported credential format');
	}
}

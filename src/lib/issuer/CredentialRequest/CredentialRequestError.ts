// OpenID4VCI Section 8.3.1.2 Credential Request Errors
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.3.1.2
export const CredentialRequestErrors = {
	InvalidRequest: 'invalid_credential_request',
	UnknownCredentialConfiguration: 'unknown_credential_configuration',
	UnknownCredentialIdentifier: 'unknown_credential_identifier',
	InvalidProof: 'invalid_proof',
	InvalidNonce: 'invalid_nonce',
	InvalidEncryptionParameters: 'invalid_encryption_parameters',
	CredentialRequestDenied: 'credential_request_denied',

	InternalServerError: 'internal_server_error',
} as const;

export type CredentialRequestError = (typeof CredentialRequestErrors)[keyof typeof CredentialRequestErrors];

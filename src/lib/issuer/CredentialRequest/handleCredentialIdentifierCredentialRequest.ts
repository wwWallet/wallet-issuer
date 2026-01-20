import { PlainIssueCredentialRequestOptions } from '../IssuerOpenID4VCITypes';
import { CredentialRequestErrors } from './CredentialRequestError';

export async function handleCredentialIdentifierCredentialRequest(opts: PlainIssueCredentialRequestOptions) {
	if ('credential_identifier' in opts.request.data && opts.request.data.credential_identifier !== undefined) {
		return {
			headers: { 'content-type': 'application/json' },
			status: 500,
			data: {
				error: CredentialRequestErrors.CredentialRequestDenied,
				error_description: "HTTP body parameter 'credential_identifier' is currently not supported",
			},
		};
	}
}

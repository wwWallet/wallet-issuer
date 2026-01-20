import { CredentialRequestError } from './CredentialRequest/CredentialRequestError';
import { PlainIssueCredentialResponse } from './IssuerOpenID4VCITypes';

export function sendError(error: CredentialRequestError, error_description?: string): PlainIssueCredentialResponse {
	return {
		headers: { 'content-type': 'application/json' },
		status: 400,
		data: {
			error: error,
			error_description: error_description,
		},
	} as PlainIssueCredentialResponse;
}

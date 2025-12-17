import { PlainIssueCredentialRequestOptions } from "../IssuerOpenID4VCI";
import { CredentialRequestErrors } from "./CredentialRequestError";

export async function handleCredentialIdentifierCredentialRequest(opts: PlainIssueCredentialRequestOptions) {
	if (opts.request.data.credential_identifier !== undefined) {
		return {
			headers: { 'Content-Type': 'application/json' },
			status: 500,
			data: {
				error: CredentialRequestErrors.CredentialRequestDenied,
				error_description: "HTTP body parameter 'credential_identifier' is currently not supported",
			}
		};
	}
}

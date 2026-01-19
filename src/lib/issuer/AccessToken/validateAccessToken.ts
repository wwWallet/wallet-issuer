import { OpenidCredentialIssuerMetadata } from "wallet-common";
import { err, ok, Result } from "wallet-common";
import { CredentialIssuerCreateOptions } from "../IssuerOpenID4VCI";
import { CredentialRequestError, CredentialRequestErrors } from "../CredentialRequest/CredentialRequestError";
import { validateDpopProof } from "./validateDpopProof";
import { PlainIssueCredentialRequestOptions } from "../IssuerOpenID4VCITypes";


/**
 * * Validates if access token is valid
 * * Checks if access token is authorized for this credentialConfigurationId
 * 
 */
export async function validateAccessToken(
	credentialConfigurationId: string,
	metadata: OpenidCredentialIssuerMetadata,
	issueRequestOpts: PlainIssueCredentialRequestOptions,
	createOpts: CredentialIssuerCreateOptions,
): Promise<Result<{ scope: string, sub: string, client_id: string, }, CredentialRequestError>> {

	try {
		const authorizationServerMetadataResponse = await fetch(createOpts.authorizationServerUrl + '/.well-known/oauth-authorization-server');
		const authorizationServerMetadata = await authorizationServerMetadataResponse.json();
		const { introspection_endpoint } = authorizationServerMetadata as { introspection_endpoint: string };
		const [tokenType, accessToken] = issueRequestOpts.request.headers["authorization"].split(' ');
		const dpopProof = issueRequestOpts.request.headers["dpop"] as string | undefined;

		try {
			// RFC7662
			const introspectionResponse = await fetch(introspection_endpoint, {
				method: 'POST',
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					"Authorization": `Basic ${createOpts.introspectionEndpointBasicAuthString}`
				},
				body: new URLSearchParams({ token: accessToken, token_type_hint: tokenType, }),
			});
			const introspectionPayload = await introspectionResponse.json();

			const { scope, sub, cnf, client_id } = introspectionPayload as { sub: string, scope: string, client_id: string, cnf?: { jkt?: string } };

			console.log("Introspection response: ", introspectionPayload)
			if (tokenType === 'DPoP' && dpopProof !== undefined) {
				const response = await validateDpopProof(dpopProof, cnf);
				if (!response.ok) {
					return response;
				}
			}
			else if (tokenType.toLocaleLowerCase() === 'DPoP'.toLowerCase() && dpopProof === undefined) {
				return err(CredentialRequestErrors.InvalidRequest, "DPoP proof is missing");
			}

			const scopeArray = scope.split(' ');
			const configurationsSupportedFiltered = Object.keys(metadata.credential_configurations_supported)
				.filter((confId) =>
					confId === credentialConfigurationId && scopeArray.includes(metadata.credential_configurations_supported[confId].scope)
				)[0];
			if (!configurationsSupportedFiltered) {
				return err(CredentialRequestErrors.CredentialRequestDenied, "Not allowed based on the released scopes");
			}

			return ok({ scope, sub, client_id });	
		}
		catch {
			return err(CredentialRequestErrors.InternalServerError, "Communication with introspection endpoint failed");
		}
	}
	catch {
		return err(CredentialRequestErrors.InternalServerError, "Could not fetch authorization server metadata");
	}

}
import { err, ok, OpenidCredentialIssuerMetadata, prependToPath, Result } from 'wallet-common';
import { CredentialIssuerCreateOptions } from '../IssuerOpenID4VCI';
import { CredentialRequestError, CredentialRequestErrors } from '../CredentialRequest/CredentialRequestError';
import { validateDpopProof } from './validateDpopProof';
import { DataStore } from '../../../store/DataStore';
import { dataStoreClient } from '../../../store/dataStoreClient';
import { PlainIssueCredentialRequestOptions } from '../IssuerOpenID4VCITypes';
import { IntrospectionResponse } from '../types';

const dpopReplayStore = new DataStore<string>(dataStoreClient, 'dpopReplay');

/**
 * * Validates if access token is valid
 * * Checks if access token is authorized for this credentialConfigurationId
 *
 */
export async function validateAccessToken(credentialConfigurationId: string, metadata: OpenidCredentialIssuerMetadata, issueRequestOpts: PlainIssueCredentialRequestOptions, createOpts: CredentialIssuerCreateOptions): Promise<Result<IntrospectionResponse & { scope: string; sub: string; client_id: string }, CredentialRequestError>> {
	try {
		const authorizationServerMetadataResponse = await fetch(prependToPath(createOpts.authorizationServerUrl, '.well-known/oauth-authorization-server') ?? '');
		const authorizationServerMetadata = await authorizationServerMetadataResponse.json();
		const { introspection_endpoint } = authorizationServerMetadata as { introspection_endpoint: string };
		const authorizationHeader = getHeader(issueRequestOpts.request.headers, 'authorization');
		if (!authorizationHeader) {
			return err(CredentialRequestErrors.InvalidRequest, 'Authorization header is missing');
		}
		const [tokenType, accessToken] = authorizationHeader.split(' ');
		if (!tokenType || !accessToken) {
			return err(CredentialRequestErrors.InvalidRequest, 'Authorization header is malformed');
		}
		const dpopProof = getHeader(issueRequestOpts.request.headers, 'dpop');

		try {
			// RFC7662
			const introspectionResponse = await fetch(introspection_endpoint, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/x-www-form-urlencoded',
					Authorization: `Basic ${createOpts.introspectionEndpointBasicAuthString}`,
				},
				body: new URLSearchParams({ token: accessToken, token_type_hint: tokenType }),
			});
			const introspectionPayload = await introspectionResponse.json();

			const { active, scope, sub, cnf, client_id } = introspectionPayload as IntrospectionResponse;

			console.log('Introspection response: ', introspectionPayload);
			if (!active) {
				return err(CredentialRequestErrors.InvalidRequest, 'Access token not active');
			}

			const normalizedTokenType = tokenType.toLowerCase();
			if (normalizedTokenType === 'dpop' && dpopProof !== undefined) {
				const expectedDpopHtu = getExpectedDpopHtu(metadata, issueRequestOpts);
				if (!expectedDpopHtu) {
					return err(CredentialRequestErrors.InternalServerError, 'Credential Issuer metadata does not contain the expected endpoint for DPoP validation');
				}

				const response = await validateDpopProof(dpopProof, cnf, {
					accessToken,
					clockTolerance: createOpts.clockTolerance,
					htu: expectedDpopHtu,
					method: 'POST',
					replayStore: dpopReplayStore,
				});
				if (!response.ok) {
					return response;
				}
			}

			if (normalizedTokenType === 'dpop' && dpopProof === undefined) {
				return err(CredentialRequestErrors.InvalidRequest, 'DPoP proof is missing');
			} else if (!scope) {
				return err(CredentialRequestErrors.InternalServerError, "Introspection response does not contain 'scope'");
			} else if (!client_id) {
				return err(CredentialRequestErrors.InternalServerError, "Introspection response does not contain 'client_id'");
			} else if (!cnf?.jkt) {
				return err(CredentialRequestErrors.InternalServerError, "Introspection response does not contain 'cnf.jkt'");
			} else if (!sub) {
				return err(CredentialRequestErrors.InternalServerError, "Introspection response does not contain 'sub'");
			}

			const scopeArray = (scope as string).split(' ');
			const configurationsSupportedFiltered = Object.keys(metadata.credential_configurations_supported).filter((confId) => confId === credentialConfigurationId && scopeArray.includes(metadata.credential_configurations_supported[confId].scope))[0];
			if (!configurationsSupportedFiltered) {
				return err(CredentialRequestErrors.CredentialRequestDenied, 'Not allowed based on the released scopes');
			}

			return ok(introspectionPayload);
		} catch {
			return err(CredentialRequestErrors.InternalServerError, 'Communication with introspection endpoint failed');
		}
	} catch {
		return err(CredentialRequestErrors.InternalServerError, 'Could not fetch authorization server metadata');
	}
}

function getExpectedDpopHtu(metadata: OpenidCredentialIssuerMetadata, issueRequestOpts: PlainIssueCredentialRequestOptions): string | undefined {
	if ('transaction_id' in issueRequestOpts.request.data) {
		return metadata.deferred_credential_endpoint;
	}

	return metadata.credential_endpoint;
}

function getHeader(headers: Record<string, unknown>, name: string): string | undefined {
	const entry = Object.entries(headers).find(([key]) => key.toLowerCase() === name.toLowerCase());
	const value = entry?.[1];
	if (Array.isArray(value)) {
		return value.join(', ');
	}
	return typeof value === 'string' ? value : undefined;
}

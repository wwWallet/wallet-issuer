import express from 'express';
import { issuer } from '../vci/issuer';
import { logger } from '../logger';
import { ZodError, z } from 'zod';
import { GrantType } from 'wallet-common';

const PRE_AUTHORIZED_CODE_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
const AUTHORIZATION_CODE_GRANT = 'authorization_code';
const INVALID_PARAMETERS_DESCRIPTION = 'Missing or invalid parameters';
const SUPPORTED_GRANTS_DESCRIPTION = 'Only authorization_code and pre-authorized_code grants are supported';

const sendCredentialOfferUriError = (
	res: express.Response,
	status: 400 | 500 | 501,
	error: 'invalid_request' | 'server_error' | 'unsupported_grant_type',
	errorDescription: string,
) => {
	return res.status(status).send({
		error,
		error_description: errorDescription,
	});
};

const credentialOfferUriRequestSchema = z.object({
	credential_configuration_ids: z.array(z.string().min(1)).length(1),
	grants: z.record(z.string(), z.unknown()),
}).strict();

const authorizationCodeGrantSchema = z.object({
	issuer_state: z.string().min(1),
}).strict();

const preAuthorizedCodeGrantSchema = z.object({
	sub: z.string().trim().min(1).max(256),
}).strict();

const logUnexpectedError = (error: unknown) => {
	if (error instanceof Error) {
		logger.error('Failed to generate credential offer URI', {
			error: {
				name: error.name,
				message: error.message,
				stack: error.stack,
			},
		});
		return;
	}

	logger.error('Failed to generate credential offer URI', { error });
};

export const credentialOfferUriHandler = async (req: express.Request, res: express.Response) => {
	try {
		const parsedBody = credentialOfferUriRequestSchema.parse(req.body);
		const grantKeys = Object.keys(parsedBody.grants);
		if (grantKeys.length !== 1 || (grantKeys[0] !== AUTHORIZATION_CODE_GRANT && grantKeys[0] !== PRE_AUTHORIZED_CODE_GRANT)) {
			return sendCredentialOfferUriError(res, 501, 'unsupported_grant_type', SUPPORTED_GRANTS_DESCRIPTION);
		}
		const grantType = grantKeys[0];
		const parsedGrant = grantType === AUTHORIZATION_CODE_GRANT
			? {
				grantType: AUTHORIZATION_CODE_GRANT as typeof AUTHORIZATION_CODE_GRANT,
				value: authorizationCodeGrantSchema.parse(parsedBody.grants[AUTHORIZATION_CODE_GRANT]),
			}
			: {
				grantType: PRE_AUTHORIZED_CODE_GRANT as typeof PRE_AUTHORIZED_CODE_GRANT,
				value: preAuthorizedCodeGrantSchema.parse(parsedBody.grants[PRE_AUTHORIZED_CODE_GRANT]),
			};

		const { metadata } = await issuer.getMetadata();
		const supportedCredentialConfigurationIds = new Set(Object.keys(metadata.credential_configurations_supported ?? {}));
		const hasUnsupportedCredentialConfigurationId = parsedBody.credential_configuration_ids
			.some((credentialConfigurationId) => !supportedCredentialConfigurationIds.has(credentialConfigurationId));

		if (hasUnsupportedCredentialConfigurationId) {
			return sendCredentialOfferUriError(res, 400, 'invalid_request', INVALID_PARAMETERS_DESCRIPTION);
		}

		const credentialConfigurationId = parsedBody.credential_configuration_ids[0];
		let generatedOffer;
		if (parsedGrant.grantType === AUTHORIZATION_CODE_GRANT) {
			generatedOffer = await issuer.generateCredentialOffer({
				credentialConfigurationId,
				grant_type: GrantType.AUTHORIZATION_CODE,
				issuerState: parsedGrant.value.issuer_state,
			});
		} else {
			const scope = metadata.credential_configurations_supported?.[credentialConfigurationId]?.scope;
			if (!scope) {
				return sendCredentialOfferUriError(res, 400, 'invalid_request', INVALID_PARAMETERS_DESCRIPTION);
			}
			generatedOffer = await issuer.generateCredentialOffer({
				credentialConfigurationId,
				grant_type: GrantType.PRE_AUTHORIZED_CODE,
				// oidc-provider uses accountId internally and exposes it as `sub`
				// through token introspection. Keep that mapping private to the issuer/AS.
				accountId: parsedGrant.value.sub,
				scope,
			});
		}

		const { credentialOfferWithReference, txCode } = generatedOffer;
		const credentialOfferReference = credentialOfferWithReference.searchParams.get('credential_offer_uri');
		if (!credentialOfferReference) {
			throw new Error('Missing credential_offer_uri in generated credential offer reference');
		}

		return res.status(201).send({
			credential_offer_uri: credentialOfferReference,
			...(txCode !== undefined ? { tx_code: txCode } : {}),
		});
	} catch (error) {
		if (error instanceof ZodError) {
			return sendCredentialOfferUriError(res, 400, 'invalid_request', INVALID_PARAMETERS_DESCRIPTION);
		}

		logUnexpectedError(error);
		return sendCredentialOfferUriError(res, 500, 'server_error', 'An unexpected error occurred');
	}
};

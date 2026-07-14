import express from 'express';
import { issuer } from '../vci/issuer';
import { logger } from '../logger';
import { ZodError, z } from 'zod';
import { GrantType } from 'wallet-common';

const PRE_AUTHORIZED_CODE_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';

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
	credential_configuration_ids: z.array(z.string().min(1)).min(1),
	grants: z.record(z.string(), z.unknown()),
});

const authorizationCodeGrantSchema = z.object({
	issuer_state: z.string().min(1),
}).strict();

const preAuthorizedCodeGrantSchema = z.object({
	account_id: z.string().trim().min(1).max(256),
}).strict();

export const credentialOfferUriHandler = async (req: express.Request, res: express.Response) => {
	try {
		const parsedBody = credentialOfferUriRequestSchema.parse(req.body);
		const grantKeys = Object.keys(parsedBody.grants);
		if (grantKeys.length !== 1 || (grantKeys[0] !== 'authorization_code' && grantKeys[0] !== PRE_AUTHORIZED_CODE_GRANT)) {
			return sendCredentialOfferUriError(res, 501, 'unsupported_grant_type', 'Only authorization_code and pre-authorized_code grants are supported');
		}

		const { metadata } = await issuer.getMetadata();
		const supportedCredentialConfigurationIds = new Set(Object.keys(metadata.credential_configurations_supported ?? {}));
		const hasUnsupportedCredentialConfigurationId = parsedBody.credential_configuration_ids
			.some((credentialConfigurationId) => !supportedCredentialConfigurationIds.has(credentialConfigurationId));

		if (hasUnsupportedCredentialConfigurationId) {
			return sendCredentialOfferUriError(res, 400, 'invalid_request', 'Missing or invalid parameters');
		}

		const credentialConfigurationId = parsedBody.credential_configuration_ids[0];
		let generatedOffer;
		if (grantKeys[0] === 'authorization_code') {
			const authorizationCodeGrant = authorizationCodeGrantSchema.parse(parsedBody.grants.authorization_code);
			generatedOffer = await issuer.generateCredentialOffer({
				credentialConfigurationId,
				grant_type: GrantType.AUTHORIZATION_CODE,
				issuerState: authorizationCodeGrant.issuer_state,
			});
		} else {
			const preAuthorizedCodeGrant = preAuthorizedCodeGrantSchema.parse(
				parsedBody.grants[PRE_AUTHORIZED_CODE_GRANT],
			);
			const scope = metadata.credential_configurations_supported?.[credentialConfigurationId]?.scope;
			if (!scope) {
				return sendCredentialOfferUriError(res, 400, 'invalid_request', 'Missing or invalid parameters');
			}
			generatedOffer = await issuer.generateCredentialOffer({
				credentialConfigurationId,
				grant_type: GrantType.PRE_AUTHORIZED_CODE,
				accountId: preAuthorizedCodeGrant.account_id,
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
			...(txCode ? { tx_code: txCode } : {}),
		});
	} catch (error) {
		if (error instanceof ZodError) {
			return sendCredentialOfferUriError(res, 400, 'invalid_request', 'Missing or invalid parameters');
		}

		logger.error(JSON.stringify(error));
		return sendCredentialOfferUriError(res, 500, 'server_error', 'An unexpected error occurred');
	}
};

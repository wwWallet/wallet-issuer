import express, { Router } from 'express';
import { issuer } from '../vci/issuer';
import { logger } from '../logger';
import { ZodError, z } from 'zod';
import { config } from '../../config';

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

export const credentialOfferUriHandler = async (req: express.Request, res: express.Response) => {
	try {
		const parsedBody = credentialOfferUriRequestSchema.parse(req.body);
		const grantKeys = Object.keys(parsedBody.grants);
		if (!grantKeys.includes('authorization_code') || grantKeys.some((grantKey) => grantKey !== 'authorization_code')) {
			return sendCredentialOfferUriError(res, 501, 'unsupported_grant_type', 'Only authorization_code grant is supported');
		}

		const authorizationCodeGrant = authorizationCodeGrantSchema.parse(parsedBody.grants.authorization_code);
		const { metadata } = await issuer.getMetadata();
		const supportedCredentialConfigurationIds = new Set(Object.keys(metadata.credential_configurations_supported ?? {}));
		const hasUnsupportedCredentialConfigurationId = parsedBody.credential_configuration_ids
			.some((credentialConfigurationId) => !supportedCredentialConfigurationIds.has(credentialConfigurationId));

		if (hasUnsupportedCredentialConfigurationId) {
			return sendCredentialOfferUriError(res, 400, 'invalid_request', 'Missing or invalid parameters');
		}

		const { credentialOfferWithReference } = await issuer.generateCredentialOffer({
			credentialConfigurationId: parsedBody.credential_configuration_ids[0], // currenly only 1 supported
			issuerState: authorizationCodeGrant.issuer_state,
		});
		const credentialOfferReference = credentialOfferWithReference.searchParams.get('credential_offer_uri');
		if (!credentialOfferReference) {
			throw new Error('Missing credential_offer_uri in generated credential offer reference');
		}

		return res.status(201).send({
			credential_offer_uri: credentialOfferReference,
		});
	} catch (error) {
		if (error instanceof ZodError) {
			return sendCredentialOfferUriError(res, 400, 'invalid_request', 'Missing or invalid parameters');
		}

		logger.error(JSON.stringify(error));
		return sendCredentialOfferUriError(res, 500, 'server_error', 'An unexpected error occurred');
	}
};

export const createApiRouter = () => {
	const router = Router();

	if (config.credentialOfferApiEnabled) {
		router.post('/credential-offer-uri', express.json(), credentialOfferUriHandler);
	}

	return router;
};

export const apiRouter = createApiRouter();

import express, { Router } from 'express';
import { config } from '../../config';
import { timingSafeEqual } from 'node:crypto';
import { credentialOfferUriHandler } from './credentialOfferUriHandler';
import { preAuthorizedCodeHandler } from './preAuthorizedCodeHandler';

const unauthorized = (res: express.Response) => {
	res.setHeader('WWW-Authenticate', 'Bearer');
	return res.status(401).send({
		error: 'unauthorized',
		error_description: 'Missing or invalid bearer token',
	});
};

export const apiBearerAuth = (
	req: express.Request,
	res: express.Response,
	next: express.NextFunction,
) => {
	const match = req.get('authorization')?.match(/^Bearer ([^\s]+)$/i);
	if (!match) {
		return unauthorized(res);
	}

	const suppliedToken = Buffer.from(match[1]);
	const expectedToken = Buffer.from(config.credentialOfferApiBearerToken);
	if (suppliedToken.length !== expectedToken.length || !timingSafeEqual(suppliedToken, expectedToken)) {
		return unauthorized(res);
	}

	return next();
};

export const preAuthorizedCodeApiBearerAuth = (
	req: express.Request,
	res: express.Response,
	next: express.NextFunction,
) => {
	const match = req.get('authorization')?.match(/^Bearer ([^\s]+)$/i);
	if (!match) {
		return unauthorized(res);
	}

	const suppliedToken = Buffer.from(match[1]);
	const expectedToken = Buffer.from(config.preAuthorizedCodeApiBearerToken);
	if (suppliedToken.length !== expectedToken.length || !timingSafeEqual(suppliedToken, expectedToken)) {
		return unauthorized(res);
	}

	return next();
};


export const createApiRouter = () => {
	const router = Router();

	if (config.credentialOfferApiEnabled) {
		if (!config.credentialOfferApiBearerToken) {
			throw new Error('CREDENTIAL_OFFER_API_BEARER_TOKEN is required when CREDENTIAL_OFFER_API_ENABLED=true');
		}

		router.use(apiBearerAuth);
		router.post('/credential-offer-uri', express.json(), credentialOfferUriHandler);
	}
	if (config.preAuthorizedCodeApiEnabled) {
		if (!config.preAuthorizedCodeApiBearerToken) {
			throw new Error('PRE_AUTHORIZED_CODE_API_BEARER_TOKEN is required when PRE_AUTHORIZED_CODE_API_ENABLED=true');
		}

		router.use(preAuthorizedCodeApiBearerAuth);
		router.post('/pre-authorized-code', express.json(), preAuthorizedCodeHandler);
	}

	return router;
};

export const apiRouter = createApiRouter();

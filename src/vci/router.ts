import { Router } from 'express';
import { logger } from '../logger';
import express from 'express';
import { issuer } from './issuer';
import { config } from '../../config';
import fs from 'fs';
import path from 'path';

export const vciRouter = Router();

const rawBase64CACert = fs.readFileSync(path.join(__dirname, '../../../keys/ca.crt'), 'utf-8')
	.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '')
	.replace(/\s+/g, '');

vciRouter.post('/nonce', async (_req, res) => {
	try {
		const response = await issuer.issueNonce();
		Object.entries(response.headers).map(([k, v]) => res.setHeader(k, v));
		res.status(response.status).send(response.data);
		logger.info('New c_nonce issued');
	} catch (e) {
		logger.error(JSON.stringify(e));
		res.status(500).send({ error: 'internal_server_error' });
	}
});

vciRouter.post('/credential', express.json(), async (req, res) => {
	try {
		logger.info('New credential request received');
		const response = await issuer.issueCredential({
			request: {
				headers: req.headers as any,
				data: req.body,
			},
		});

		logger.info('Credential response sent');
		Object.entries(response.headers).map(([k, v]) => res.setHeader(k, v));
		res.status(response.status).send(response.data);
	} catch (e) {
		console.error(e);
		logger.error(JSON.stringify(e));
		res.status(500).send({ error: 'internal_server_error' });
	}
});

vciRouter.post('/deferred-credential', express.json(), async (req, res) => {
	try {
		logger.info('New deferred request received');
		const response = await issuer.issueCredential({
			request: {
				headers: req.headers as any,
				data: req.body,
			},
		});

		logger.info('Deferred response sent');
		Object.entries(response.headers).map(([k, v]) => res.setHeader(k, v));
		res.status(response.status).send(response.data);
	} catch (e) {
		console.error(e);
		logger.error(JSON.stringify(e));
		res.status(500).send({ error: 'internal_server_error' });
	}
});

vciRouter.get('/credential-offer/:id', async (req, res) => {
	const offerId = req.params.id;
	const offer = await issuer.getCredentialOffer(offerId, config.revokeCredentialOffers);
	logger.info('Credential offer retrieved');
	res.status(200).send(offer);
});

vciRouter.get('/.well-known/openid-credential-issuer', async (_req, res) => {
	try {
		const { metadata } = await issuer.getMetadata();
		res.status(200).send(metadata);
	} catch (e) {
		logger.error(JSON.stringify(e));
		res.status(500).send({ error: 'internal_server_error' });
	}
});


vciRouter.get('/mdoc-iacas', async (_req, res) => {
	return res.send({
		iacas: [ rawBase64CACert ]
	});
});

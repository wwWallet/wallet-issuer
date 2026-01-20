import { Router } from 'express';
import { logger } from '../logger';
import express from 'express';
import { issuer } from './issuer';
export const vciRouter = Router();

vciRouter.get('/credential-offer/:id', async (req, res) => {
	try {
		const id = req.params.id as string;
		if (!id) {
			res.status(400).send({ error: 'Not found' });
		}
		const obj = await issuer.getCredentialOffer(id, true);
		res.status(200).send(obj);
	} catch (e) {
		logger.error(JSON.stringify(e));
		res.status(500).send({ error: 'internal_server_error' });
	}
});

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

vciRouter.get('/.well-known/openid-credential-issuer', async (_req, res) => {
	try {
		const metadata = await issuer.getMetadata(false);

		res.status(200).send(metadata);
	} catch (e) {
		logger.error(JSON.stringify(e));
		res.status(500).send({ error: 'internal_server_error' });
	}
});

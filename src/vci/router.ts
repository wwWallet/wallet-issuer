import { Router } from 'express';
import { logger } from '../logger';
import express from 'express';
import { issuer } from './issuer';
import { config } from '../../config';
import fs from 'fs';
import path from 'path';

const log = logger.child({ module: 'VCI' });

export const vciRouter = Router();

const rawBase64CACert = fs
	.readFileSync(path.join(__dirname, '../../../keys/ca.crt'), 'utf-8')
	.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '')
	.replace(/\s+/g, '');

vciRouter.post('/nonce', async (_req, res) => {
	try {
		const response = await issuer.issueNonce();
		Object.entries(response.headers).map(([k, v]) => res.setHeader(k, v));
		res.status(response.status).send(response.data);
		log.debug('New c_nonce issued');
	} catch (e) {
		log.error({ err: e }, 'Nonce endpoint failed');
		res.status(500).send({ error: 'internal_server_error' });
	}
});

vciRouter.post(
	'/credential',
	express.raw({ type: 'application/jwt' }),
	express.json(),
	async (req, res) => {
		try {
			log.debug('Credential request received');
			const response = await issuer.issueCredential({
				request: {
					headers: req.headers as any,
					data: Buffer.isBuffer(req.body) ? req.body.toString('utf8') : req.body,
				},
			});

			log.info({ status: response.status }, 'Credential response sent');
			Object.entries(response.headers).map(([k, v]) => res.setHeader(k, v));
			res.status(response.status).send(response.data);
		} catch (e) {
			log.error({ err: e }, 'Credential endpoint failed');
			res.status(500).send({ error: 'internal_server_error' });
		}
	},
);

vciRouter.post(
	'/deferred-credential',
	express.raw({ type: 'application/jwt' }),
	express.json(),
	async (req, res) => {
		try {
			log.debug('Deferred credential request received');
			const response = await issuer.issueCredential({
				request: {
					headers: req.headers as any,
					data: Buffer.isBuffer(req.body) ? req.body.toString('utf8') : req.body,
				},
			});

			log.info({ status: response.status }, 'Deferred credential response sent');
			Object.entries(response.headers).map(([k, v]) => res.setHeader(k, v));
			res.status(response.status).send(response.data);
		} catch (e) {
			log.error({ err: e }, 'Deferred credential endpoint failed');
			res.status(500).send({ error: 'internal_server_error' });
		}
	},
);

vciRouter.get('/credential-offer/:id', async (req, res) => {
	try {
		const id = req.params.id as string;
		if (!id) {
			res.status(400).send({ error: 'Not found' });
		}
		const obj = await issuer.getCredentialOffer(id, config.revokeCredentialOffers);
		res.status(200).send(obj);
	} catch (e) {
		log.error({ err: e }, 'Credential offer retrieval failed');
		res.status(500).send({ error: 'internal_server_error' });
	}
});

vciRouter.get('/mdoc-iacas', async (_req, res) => {
	return res.send({
		iacas: [rawBase64CACert],
	});
});

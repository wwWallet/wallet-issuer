import { Router } from "express";
import { logger } from "../logger";
import express from 'express';
import { issuer } from "./issuer";
import path from "path";
export const vciRouter = Router();


vciRouter.get('/credential-offer/:id', async (req, res) => {
	const id = req.params.id as string;
	if (!id) {
		res.status(400).send({ error: "Not found" });
	}
	const obj = await issuer.getCredentialOffer(id, true);
	res.status(200).send(obj);
});

vciRouter.post('/nonce', async (_req, res) => {
	const response = await issuer.issueNonce();
	Object.entries(response.headers).map(([k, v]) => res.setHeader(k, v));
	res.status(response.status).send(response.data);
	logger.info("New c_nonce issued");
});

vciRouter.post('/credential', express.json(), async (req, res) => {
	logger.info("New credential request received");
	const response = await issuer.issueCredential({
		request: {
			headers: req.headers as any,
			data: req.body,
		},
	});

	Object.entries(response.headers).map(([k, v]) => res.setHeader(k, v));
	res.status(response.status).send(response.data);
});

vciRouter.post('/deferred-credential', express.json(), async (req, res) => {
	logger.info("New deferred request received");
	const response = await issuer.issueCredential({
		request: {
			headers: req.headers as any,
			data: req.body,
		},
	});

	Object.entries(response.headers).map(([k, v]) => res.setHeader(k, v));
	res.status(response.status).send(response.data);
});


vciRouter.use(
	'/.well-known',
	(_, res, next) => {
		res.setHeader('Content-Type', 'application/json')
		next();
	},
	express.static(path.join(__dirname, '../../../public/.well-known/'))
);

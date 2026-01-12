import { Router } from "express";
import { logger } from "../logger";
import express from 'express';
import { issuer } from "./issuer";
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

	logger.info("New credential has been issued");
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

	logger.info("Deferred response sent");
	Object.entries(response.headers).map(([k, v]) => res.setHeader(k, v));
	res.status(response.status).send(response.data);
});


let metadata: any = undefined;

vciRouter.get('/.well-known/openid-credential-issuer', async (_req, res) => {
	if (!metadata) {
		metadata = await issuer.getMetadata();
	}
	res.status(200).send(metadata);
});	


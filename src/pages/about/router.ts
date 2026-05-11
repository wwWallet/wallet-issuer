import { Router } from 'express';
import { prependToPath } from 'wallet-common';
import { config } from '../../../config';

export const aboutRouter = Router();

aboutRouter.get('/about', (_req, res) => {
	const baseUrl = config.url;
	const credentialIssuerMetadataUrl = prependToPath(baseUrl, '.well-known/openid-credential-issuer');
	const jwtVcIssuerMetadataUrl = prependToPath(baseUrl, '.well-known/jwt-vc-issuer');

	res.render('about', {
		title: 'About',
		baseUrl,
		credentialIssuerMetadataUrl,
		jwtVcIssuerMetadataUrl
	});
});

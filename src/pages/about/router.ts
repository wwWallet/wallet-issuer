import { Router } from 'express';
import { prependToPath } from 'wallet-common';
import { config } from '../../../config';

export const aboutRouter = Router();

aboutRouter.get('/about', (_req, res) => {
	const credentialIssuerIdentifier = config.issuerIdentifier;
	const credentialIssuerMetadataUrl = prependToPath(credentialIssuerIdentifier, '.well-known/openid-credential-issuer');
	const jwtVcIssuerMetadataUrl = prependToPath(credentialIssuerIdentifier, '.well-known/jwt-vc-issuer');

	res.render('about', {
		title: 'About',
		credentialIssuerIdentifier,
		credentialIssuerMetadataUrl,
		jwtVcIssuerMetadataUrl
	});
});

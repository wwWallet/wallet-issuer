import { Router } from 'express';
import { issuer } from '../../vci/issuer';
import { fromBase64Url, GrantType } from 'wallet-common';
import { config } from '../../../config';
import { logger } from '../../logger';

export const landingRouter = Router();
const decoder = new TextDecoder();

landingRouter.get('/', async (_req, res) => {
	const { metadata } = await issuer.getMetadata();
	res.render('home', { metadata });
});

landingRouter.get('/offer/:id', async (req, res) => {
	const credentialConfigurationIdB54U = req.params.id;
	if (!credentialConfigurationIdB54U) {
		res.redirect('/');
		return;
	}
	const credentialConfigurationId = decoder.decode(fromBase64Url(credentialConfigurationIdB54U));
	const { metadata } = await issuer.getMetadata();
	const targetMetadata = metadata.credential_configurations_supported?.[credentialConfigurationId];

	// Default: use the configuration id itself
	let credentialName = credentialConfigurationId;

	// If a display name exists, prefer it
	const displayArr = targetMetadata?.credential_metadata?.display;
	if (Array.isArray(displayArr) && displayArr.length > 0) {
		const d = displayArr[0];
		if (typeof d?.name === "string" && d.name.trim()) {
			credentialName = d.name;
		}
	}

	const { credentialOfferWithReference } = await issuer.generateCredentialOffer({ credentialConfigurationId: credentialConfigurationId });
	const ref = credentialOfferWithReference.searchParams.get('credential_offer_uri');
	const credentialOfferWithReferenceForWwwallet = new URL(config.wwwalletURL);
	if (ref) {
		credentialOfferWithReferenceForWwwallet.searchParams.append('credential_offer_uri', ref);
	}
	else {
		logger.error("No credential offer refference found");
		res.render('error', { error: "invalid-credential-offer" });
		return;
	}
	res.render('offer', { credentialOfferWithReference, credentialOfferWithReferenceForWwwallet, credentialName });
});

landingRouter.get('/pre-authorized-offer/:id', async (req, res) => {
	const credentialConfigurationIdB64U = req.params.id;
	if (!credentialConfigurationIdB64U) {
		res.redirect('/');
		return;
	}
	const credentialConfigurationId = decoder.decode(fromBase64Url(credentialConfigurationIdB64U));
	const { metadata } = await issuer.getMetadata();
	const targetMetadata = metadata.credential_configurations_supported?.[credentialConfigurationId];

	const params = new URLSearchParams({
		client_id: 'pest',
		response_type: 'code',
		scope: `openid ${targetMetadata.scope}`,
		state: JSON.stringify({
			credential_configuration_id: credentialConfigurationId
		}),
		redirect_uri: 'http://localhost:8003/callback',
	});

	res.redirect(`http://localhost:6060/auth?${params}`);

});

landingRouter.get('/callback', async (req, res) => {
	const { code, state } = req.query;

	const tokenResponse = await fetch('http://localhost:6060/token', {
		method: 'POST',
		headers: {
			Authorization:
				'Basic ' + Buffer.from('pest:test').toString('base64'),
			'Content-Type': 'application/x-www-form-urlencoded',
		},
		body: new URLSearchParams({
			grant_type: 'authorization_code',
			code: String(code),
			redirect_uri: 'http://localhost:8003/callback',
		}),
	});

	const tokens = await tokenResponse.json();

	if (tokens.error) {
		res.type('html').send(`<h1>Authorization complete</h1><h2>Authorization Response</h2><pre>${JSON.stringify({ code, state }, null, 2)}</pre><h2>Token Response</h2><pre>${JSON.stringify(tokens, null, 2)}</pre>`);
		return;
	}

	const parsedState = await JSON.parse(state as any);
	const credentialConfigurationId = parsedState['credential_configuration_id'];

	const { metadata } = await issuer.getMetadata();
	const targetMetadata = metadata.credential_configurations_supported?.[credentialConfigurationId];

	// Default: use the configuration id itself
	let credentialName = credentialConfigurationId;

	// If a display name exists, prefer it
	const displayArr = targetMetadata?.credential_metadata?.display;
	if (Array.isArray(displayArr) && displayArr.length > 0) {
		const d = displayArr[0];
		if (typeof d?.name === "string" && d.name.trim()) {
			credentialName = d.name;
		}
	}

	const { credentialOfferWithReference, txCode } = await issuer.generateCredentialOffer({ credentialConfigurationId, grant_type: GrantType.PRE_AUTHORIZED_CODE });
	const ref = credentialOfferWithReference.searchParams.get('credential_offer_uri');
	const credentialOfferWithReferenceForWwwallet = new URL(config.wwwalletURL);
	if (ref) {
		credentialOfferWithReferenceForWwwallet.searchParams.append('credential_offer_uri', ref);
	}
	else {
		logger.error("No credential offer refference found");
		res.render('error', { error: "invalid-credential-offer" });
		return;
	}
	res.render('offer', { credentialOfferWithReference, credentialOfferWithReferenceForWwwallet, credentialName, txCode });
});

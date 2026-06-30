import { Response, Router } from 'express';
import { importJWK, jwtVerify } from 'jose';
import { issuer } from '../../vci/issuer';
import { fromBase64Url, GrantType } from 'wallet-common';
import { config } from '../../../config';
import { logger } from '../../logger';

export const landingRouter = Router();
const decoder = new TextDecoder();

type VerifiedPayload = {
	sub?: string;
};

async function verifyPayload(tokenRequestBody: { error?: unknown; id_token?: unknown }, res: Response): Promise<VerifiedPayload | null> {
	if (tokenRequestBody.error) {
		res.render('error', {
			error: 'Token request failed',
			errorDescription: JSON.stringify(tokenRequestBody, null, 2),
		});
		return null;
	}

	const idToken = String(tokenRequestBody.id_token || '');
	if (!idToken) {
		res.render('error', {
			error: 'Missing id_token',
			errorDescription: 'Authorization server did not return an id_token.',
		});
		return null;
	}

	const discoveryResponse = await fetch(`${config.authorizationServerUrl}/.well-known/openid-configuration`);
	if (!discoveryResponse.ok) {
		res.render('error', {
			error: 'Discovery failed',
			errorDescription: `Unable to fetch OpenID configuration from ${config.authorizationServerUrl}`,
		});
		return null;
	}

	const discovery = await discoveryResponse.json();
	const jwksResponse = await fetch(discovery.jwks_uri);
	if (!jwksResponse.ok) {
		res.render('error', {
			error: 'JWKS fetch failed',
			errorDescription: `Unable to fetch JWKS from ${discovery.jwks_uri}`,
		});
		return null;
	}

	const jwks = await jwksResponse.json();
	const [header] = idToken.split('.');
	const decodedHeader = JSON.parse(Buffer.from(header, 'base64url').toString('utf8')) as { kid?: string; alg?: string };
	const jwk = jwks.keys?.find((key: any) => key.kid === decodedHeader.kid);
	if (!jwk) {
		res.render('error', {
			error: 'Invalid id_token',
			errorDescription: 'Unable to find a matching JWK for id_token header.',
		});
		return null;
	}

	const publicKey = await importJWK(jwk, decodedHeader.alg ?? 'RS256');
	try {
		const { payload } = await jwtVerify(idToken, publicKey, {
			audience: 'wallet_issuer',
			issuer: discovery.issuer,
		});

		const accountId = String(payload.sub ?? '');
		if (!accountId) {
			res.render('error', {
				error: 'Invalid id_token',
				errorDescription: 'id_token is missing the subject (sub) claim.',
			});
			return null;
		}

		return payload as VerifiedPayload;
	} catch (error) {
		res.render('error', {
			error: 'Invalid id_token',
			errorDescription: String(error),
		});
		return null;
	}
}

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
	const scope = targetMetadata.scope;

	const params = new URLSearchParams({
		client_id: config.preAuthorizedCodeGrantClientId,
		response_type: 'code',
		scope: `openid ${scope}`,
		state: JSON.stringify({
			credential_configuration_id: credentialConfigurationId
		}),
		redirect_uri: `${config.url}/callback`,
	});

	res.redirect(`${config.authorizationServerUrl}/auth?${params}`);

});

landingRouter.get('/callback', async (req, res) => {
	const { code, state } = req.query;

	const tokenResponse = await fetch(`${config.authorizationServerUrl}/token`, {
		method: 'POST',
		headers: {
			Authorization:
				'Basic ' + Buffer.from(`${config.preAuthorizedCodeGrantClientId}:${config.preAuthorizedCodeGrantClientSecret}`).toString('base64'),
			'Content-Type': 'application/x-www-form-urlencoded',
		},
		body: new URLSearchParams({
			grant_type: 'authorization_code',
			code: String(code),
			redirect_uri: `${config.url}/callback`,
		}),
	});

	const tokenRequestBody = await tokenResponse.json();
	const verifiedPayload = await verifyPayload(tokenRequestBody, res);
	if (!verifiedPayload) {
		return;
	}

	const accountId = String(verifiedPayload.sub);
	if (!accountId) {
		res.render('error', {
			error: 'Invalid id_token',
			errorDescription: 'id_token is missing the subject (sub) claim.',
		});
		return;
	}

	const parsedState = await JSON.parse(state as any);
	const credentialConfigurationId = parsedState['credential_configuration_id'];

	const { metadata } = await issuer.getMetadata();
	const targetMetadata = metadata.credential_configurations_supported?.[credentialConfigurationId];

	let credentialName = credentialConfigurationId;

	const displayArr = targetMetadata?.credential_metadata?.display;
	if (Array.isArray(displayArr) && displayArr.length > 0) {
		const d = displayArr[0];
		if (typeof d?.name === "string" && d.name.trim()) {
			credentialName = d.name;
		}
	}

	const { credentialOfferWithReference, txCode } = await issuer.generateCredentialOffer({ credentialConfigurationId, grant_type: GrantType.PRE_AUTHORIZED_CODE, accountId });
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

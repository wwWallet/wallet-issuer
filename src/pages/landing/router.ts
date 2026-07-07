import { Response, Router } from 'express';
import { importJWK, jwtVerify } from 'jose';
import { issuer } from '../../vci/issuer';
import { fromBase64Url, GrantType, MemoryStore } from 'wallet-common';
import type { CredentialConfigurationSupported } from 'wallet-common';
import { config } from '../../../config';
import { locale } from '../../../config/locale';
import { logger } from '../../logger';
import { randomUUID } from 'node:crypto';

export const landingRouter = Router();
const decoder = new TextDecoder();

type OfferResult = {
	id: string;
	credentialOfferWithReference: URL;
	credentialOfferWithReferenceForWwwallet: URL;
	credentialName: string;
	grantTypeLabel: string;
	pageTitle: string;
	txCode?: string;
	expiresAt: number;
};

const offerResults = new MemoryStore<string, OfferResult>(100000);

async function removeExpiredOfferResults(now = Date.now()): Promise<void> {
	const results = await offerResults.getAll();
	await Promise.all(results.map(async (result) => {
		if (result.expiresAt <= now) {
			await offerResults.delete(result.id);
		}
	}));
}

async function storeOfferResult(result: Omit<OfferResult, 'id' | 'expiresAt'>): Promise<string> {
	const id = randomUUID();
	const now = Date.now();
	await removeExpiredOfferResults(now);
	await offerResults.set(id, { id, ...result, expiresAt: now + config.preAuthorizedCodeGrantTtlMs });
	return id;
}

type VerifiedPayload = {
	sub?: string;
};

type CredentialOfferDisplay = {
	credentialName: string;
	credentialDescription: string;
	credentialFormatLabel: string;
	credentialLogoImage: string;
	credentialVisualStyle: string;
};

const isSafeColor = (value: unknown): value is string =>
	typeof value === 'string' && /^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/.test(value.trim());

const getFormatLabel = (format: string | undefined): string => {
	if (format === 'mso_mdoc') {
		return 'mDoc';
	}

	if (format && format.includes('sd-jwt')) {
		return 'SD-JWT VC';
	}

	if (format === 'jwt_vc_json') {
		return 'JWT VC';
	}

	return format || 'Credential';
};

const getCredentialOfferDisplay = (
	credentialConfigurationId: string,
	targetMetadata?: CredentialConfigurationSupported,
): CredentialOfferDisplay => {
	const display = targetMetadata?.credential_metadata?.display?.[0];
	const accentColor = isSafeColor(display?.background_color) ? display.background_color.trim() : '#dbeafe';
	const textColor = isSafeColor(display?.text_color) ? display.text_color.trim() : '#00246b';

	return {
		credentialName: display?.name?.trim() || credentialConfigurationId,
		credentialDescription: display?.description?.trim() || '',
		credentialFormatLabel: getFormatLabel(targetMetadata?.format),
		credentialLogoImage: display?.logo?.uri || '',
		credentialVisualStyle: `--credential-accent: ${accentColor}; --credential-text: ${textColor};`,
	};
};

const getWwwalletCredentialOfferUrl = (credentialOfferWithReference: URL): URL | null => {
	const ref = credentialOfferWithReference.searchParams.get('credential_offer_uri');
	if (!ref) {
		return null;
	}

	const credentialOfferWithReferenceForWwwallet = new URL(config.wwwalletURL);
	credentialOfferWithReferenceForWwwallet.searchParams.append('credential_offer_uri', ref);
	return credentialOfferWithReferenceForWwwallet;
};

async function verifyPayload(tokenRequestBody: { error?: unknown; id_token?: unknown }, res: Response): Promise<VerifiedPayload | null> {
	const authErrorObj = {
		error: 'Unable to authenticate',
		errorDescription: 'Please try again'
	}
	if (tokenRequestBody.error) {
		console.log({
			error: 'Token request failed',
			errorDescription: JSON.stringify(tokenRequestBody, null, 2),
		});
		res.render('error', authErrorObj);
		return null;
	}

	const idToken = String(tokenRequestBody.id_token || '');
	if (!idToken) {
		console.log({
			error: 'Missing id_token',
			errorDescription: 'Authorization server did not return an id_token.',
		});
		res.render('error', authErrorObj);
		return null;
	}

	const discoveryResponse = await fetch(`${config.authorizationServerUrl}/.well-known/openid-configuration`);
	if (!discoveryResponse.ok) {
		console.log({
			error: 'Discovery failed',
			errorDescription: `Unable to fetch OpenID configuration from ${config.authorizationServerUrl}`,
		});
		res.render('error', authErrorObj);

		return null;
	}

	const discovery = await discoveryResponse.json();
	const jwksResponse = await fetch(discovery.jwks_uri);
	if (!jwksResponse.ok) {
		console.log({
			error: 'JWKS fetch failed',
			errorDescription: `Unable to fetch JWKS from ${discovery.jwks_uri}`,
		});
		res.render('error', authErrorObj);
		return null;
	}

	const jwks = await jwksResponse.json();
	const [header] = idToken.split('.');
	const decodedHeader = JSON.parse(Buffer.from(header, 'base64url').toString('utf8')) as { kid?: string; alg?: string };
	const jwk = jwks.keys?.find((key: any) => key.kid === decodedHeader.kid);
	if (!jwk) {
		console.log({
			error: 'Invalid id_token',
			errorDescription: 'Unable to find a matching JWK for id_token header.',
		});
		res.render('error', authErrorObj);
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
			console.log({
				error: 'Invalid id_token',
				errorDescription: 'id_token is missing the subject (sub) claim.',
			});
			res.render('error', authErrorObj);
			return null;
		}

		return payload as VerifiedPayload;
	} catch (error) {
		console.log({
			error: 'Invalid id_token',
			errorDescription: String(error),
		});
		res.render('error', authErrorObj);
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
	const credentialDisplay = getCredentialOfferDisplay(credentialConfigurationId, targetMetadata);

	const { credentialOfferWithReference } = await issuer.generateCredentialOffer({ credentialConfigurationId: credentialConfigurationId });
	const credentialOfferWithReferenceForWwwallet = getWwwalletCredentialOfferUrl(credentialOfferWithReference);
	if (!credentialOfferWithReferenceForWwwallet) {
		logger.error("No credential offer reference found");
		res.render('error', { error: "invalid-credential-offer" });
		return;
	}
	res.render('offer', {
		credentialOfferWithReference,
		credentialOfferWithReferenceForWwwallet,
		...credentialDisplay,
		grantTypeLabel: locale.offer.authorizationCodeGrant,
		pageTitle: `${credentialDisplay.credentialName} offer`,
	});
});

landingRouter.get('/initialize-pre-authorized-offer/:id', async (req, res) => {
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

landingRouter.get('/pre-authorized-offer/:id', async (req, res) => {
	const now = Date.now();
	await removeExpiredOfferResults(now);
	const offerResult = await offerResults.get(req.params.id);
	if (!offerResult || offerResult.expiresAt <= now) {
		await offerResults.delete(req.params.id);
		res.render('error', { error: 'invalid-credential-offer' });
		return;
	}

	res.render('offer', offerResult);
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

	let parsedState: { credential_configuration_id?: string };
	try {
		parsedState = JSON.parse(String(state));
	} catch {
		res.render('error', { error: 'invalid-credential-offer' });
		return;
	}
	const credentialConfigurationId = parsedState['credential_configuration_id'];
	if (!credentialConfigurationId) {
		res.render('error', { error: 'invalid-credential-offer' });
		return;
	}

	const { metadata } = await issuer.getMetadata();
	const targetMetadata = metadata.credential_configurations_supported?.[credentialConfigurationId];
	if (!targetMetadata) {
		res.render('error', { error: 'invalid-credential-offer' });
		return;
	}
	const scope = targetMetadata.scope;
	const credentialDisplay = getCredentialOfferDisplay(credentialConfigurationId, targetMetadata);

	const { credentialOfferWithReference, txCode } = await issuer.generateCredentialOffer({ credentialConfigurationId, grant_type: GrantType.PRE_AUTHORIZED_CODE, accountId, scope });
	const credentialOfferWithReferenceForWwwallet = getWwwalletCredentialOfferUrl(credentialOfferWithReference);
	if (!credentialOfferWithReferenceForWwwallet) {
		logger.error("No credential offer reference found");
		res.render('error', { error: "invalid-credential-offer" });
		return;
	}
	const offerResultId = await storeOfferResult({
		credentialOfferWithReference,
		credentialOfferWithReferenceForWwwallet,
		...credentialDisplay,
		txCode,
		grantTypeLabel: locale.offer.preAuthorizedCodeGrant,
		pageTitle: `${credentialDisplay.credentialName} offer`,
	});

	res.redirect(303, `/pre-authorized-offer/${offerResultId}`);
});

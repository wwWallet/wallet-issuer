import { Response, Router } from 'express';
import { importJWK, jwtVerify } from 'jose';
import { issuer } from '../../vci/issuer';
import { fromBase64Url, GrantType } from 'wallet-common';
import type { CredentialConfigurationSupported } from 'wallet-common';
import { config } from '../../../config';
import { locale } from '../../../config/locale';
import { logger } from '../../logger';
import { randomUUID } from 'node:crypto';
import { DataStore } from '../../store/DataStore';
import { dataStoreClient } from '../../store/dataStoreClient';

export const landingRouter = Router();
const decoder = new TextDecoder();

type OfferResult = {
	credentialOfferWithReference: URL;
	credentialOfferWithReferenceForWwwallet: URL;
	credentialName: string;
	grantTypeLabel: string;
	pageTitle: string;
	txCode?: string;
};

type SerializedOfferResult = Omit<OfferResult, 'credentialOfferWithReference' | 'credentialOfferWithReferenceForWwwallet'> & {
	credentialOfferWithReference: string;
	credentialOfferWithReferenceForWwwallet: string;
};

const deserializeOfferResult = (value: string): OfferResult => {
	const result = JSON.parse(value) as SerializedOfferResult;
	return {
		...result,
		credentialOfferWithReference: new URL(result.credentialOfferWithReference),
		credentialOfferWithReferenceForWwwallet: new URL(result.credentialOfferWithReferenceForWwwallet),
	};
};

const offerResults = new DataStore<OfferResult>(
	dataStoreClient,
	'landingPreAuthorizedOffer',
	JSON.stringify,
	deserializeOfferResult,
);

async function storeOfferResult(result: OfferResult): Promise<string> {
	const id = randomUUID();
	await offerResults.set(id, result, config.preAuthorizedCodeGrantTtlMs);
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

const decodeCredentialConfigurationId = (encodedId: string): string | null => {
	try {
		return decoder.decode(fromBase64Url(encodedId));
	} catch {
		return null;
	}
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
	const credentialConfigurationId = decodeCredentialConfigurationId(credentialConfigurationIdB54U);
	if (!credentialConfigurationId) {
		res.render('error', {
			error: 'Invalid Credential Offer',
			errorDescription: 'The credential offer link is invalid. Please return to the home page and try again.',
		});
		return;
	}
	const { metadata } = await issuer.getMetadata();
	const targetMetadata = metadata.credential_configurations_supported?.[credentialConfigurationId];
	if (!targetMetadata) {
		res.render('error', {
			error: 'Invalid Credential Offer',
			errorDescription: 'The requested credential is not available. Please return to the home page and choose another credential.',
		});
		return;
	}
	const credentialDisplay = getCredentialOfferDisplay(credentialConfigurationId, targetMetadata);

	const { credentialOfferWithReference } = await issuer.generateCredentialOffer({ credentialConfigurationId: credentialConfigurationId });
	const credentialOfferWithReferenceForWwwallet = getWwwalletCredentialOfferUrl(credentialOfferWithReference);
	if (!credentialOfferWithReferenceForWwwallet) {
		logger.error("No credential offer reference found");
		res.render('error', {
			error: 'Invalid Credential Offer',
			errorDescription: 'The credential offer could not be generated. Please return to the home page and try again.',
		});
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
	const credentialConfigurationId = decodeCredentialConfigurationId(credentialConfigurationIdB64U);
	if (!credentialConfigurationId) {
		res.render('error', {
			error: 'Invalid Credential Offer',
			errorDescription: 'The credential offer link is invalid. Please return to the home page and try again.',
		});
		return;
	}
	const { metadata } = await issuer.getMetadata();
	const targetMetadata = metadata.credential_configurations_supported?.[credentialConfigurationId];
	if (!targetMetadata) {
		res.render('error', {
			error: 'Invalid Credential Offer',
			errorDescription: 'The requested credential is not available. Please return to the home page and choose another credential.',
		});
		return;
	}
	const scope = targetMetadata.scope;
	if (!scope) {
		logger.error(`Credential configuration ${credentialConfigurationId} does not define a scope`);
		res.render('error', {
			error: 'Credential Configuration Error',
			errorDescription: 'This credential is temporarily unavailable. Please return to the home page and choose another credential.',
		});
		return;
	}

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
	const offerResult = await offerResults.get(req.params.id);
	if (!offerResult) {
		res.render('error', {
			error: 'Invalid Credential Offer',
			errorDescription: 'This credential offer is not valid. Please authenticate again to generate a new offer.',
		});
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
		res.render('error', {
			error: 'Invalid Credential Offer',
			errorDescription: 'Unable to determine which credential to offer. Please return to the home page and try again.',
		});
		return;
	}
	const credentialConfigurationId = parsedState['credential_configuration_id'];
	if (!credentialConfigurationId) {
		res.render('error', {
			error: 'Invalid Credential Offer',
			errorDescription: 'Unable to determine which credential to offer. Please return to the home page and try again.',
		});
		return;
	}

	const { metadata } = await issuer.getMetadata();
	const targetMetadata = metadata.credential_configurations_supported?.[credentialConfigurationId];
	if (!targetMetadata) {
		res.render('error', {
			error: 'Invalid Credential Offer',
			errorDescription: 'The requested credential is not available. Please return to the home page and choose another credential.',
		});
		return;
	}
	const scope = targetMetadata.scope;
	const credentialDisplay = getCredentialOfferDisplay(credentialConfigurationId, targetMetadata);

	const { credentialOfferWithReference, txCode } = await issuer.generateCredentialOffer({ credentialConfigurationId, grant_type: GrantType.PRE_AUTHORIZED_CODE, accountId, scope });
	const credentialOfferWithReferenceForWwwallet = getWwwalletCredentialOfferUrl(credentialOfferWithReference);
	if (!credentialOfferWithReferenceForWwwallet) {
		logger.error("No credential offer reference found");
		res.render('error', {
			error: 'Invalid Credential Offer',
			errorDescription: 'The credential offer could not be generated. Please return to the home page and try again.',
		});
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

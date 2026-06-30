import dotenv from 'dotenv';
import { TxCode } from 'wallet-common';
dotenv.config({ quiet: true });

const url = String(process.env.SERVICE_URL || 'default_url');
const supportedCredentialScopesWhitelist = (process.env.SUPPORTED_CREDENTIAL_SCOPES_WHITELIST ?? '')
	.split(',')
	.map((scope) => scope.trim())
	.filter(Boolean);
const rawIssuerPath = process.env.ISSUER_PATH?.trim() || "";
const issuerPath = rawIssuerPath
	? `/${rawIssuerPath.replace(/^\/+|\/+$/g, "")}`
	: "";

const preAuthorizedCodeApiEnabled = process.env.PRE_AUTHORIZED_CODE_API_ENABLED?.trim() === 'true';

function getTxCodeObject(): TxCode | undefined {

	let txCode;

	if (!preAuthorizedCodeApiEnabled) {
		return txCode;
	}

	const txCodeEnabled = process.env.PRE_AUTHORIZED_CODE_GRANT_TX_CODE?.trim() === 'true';
	if (!txCodeEnabled) {
		return txCode;
	} else {
		txCode = {};
	}

	const txCodeInputMode = process.env.PRE_AUTHORIZED_CODE_GRANT_INPUT_MODE?.trim();
	switch (txCodeInputMode) {
		case 'text':
			txCode = {
				input_mode: 'text'
			}
			break;
		case 'numeric':
		default:
			txCode = {
				input_mode: 'numeric'
			}
			break;
	}

	const txCodeLength = process.env.PRE_AUTHORIZED_CODE_GRANT_LENGTH;
	if (txCodeLength) {
		txCode = {
			...txCode,
			length: Number(txCodeLength)
		}
	}

	const txCodeDescription = process.env.PRE_AUTHORIZED_CODE_GRANT_DESCRIPTION;
	if (txCodeDescription) {
		txCode = {
			...txCode,
			description: txCodeDescription
		}
	}
	return txCode as TxCode;
}

export const config = {
	url: url,
	issuerIdentifier: `${url}${issuerPath}`,
	port: parseInt(process.env.SERVICE_PORT || '8003'),
	authorizationServerUrl: String(process.env.AUTHORIZATION_SERVER_URL || 'default_url'),
	credentialIssuanceBatchSize: parseInt(process.env.CREDENTIAL_ISSUANCE_BATCH_SIZE || '1', 10),
	introspectionEndpointBasicAuthString: String(process.env.INTROSPECTION_ENDPOINT_BASIC_AUTH_HEADER || 'default_url'),
	jweEncryptionAlg: String(process.env.JWE_ENCRYPTION_ALG || 'ECDH-ES'),
	display: [
		{
			name: String(process.env.DISPLAY_NAME || 'wwWallet Issuer'),
			locale: String(process.env.DISPLAY_LOCALE || 'en-US'),
			logo: {
				uri: String(process.env.DISPLAY_LOGO_URI || url + '/images/logo.png'),
			},
		},
	],
	wwwalletURL: process.env.WWWALLET_URL || 'http://localhost:3000/cb',
	clockTolerance: parseInt(process.env.CLOCK_TOLERANCE || '60', 10),
	deferredCredentialResponseInterval: parseInt(process.env.DEFERRED_CREDENTIAL_RESPONSE_INTERVAL_SEC || '60', 10),
	siteConfig: {
		name: process.env.SITE_NAME || 'wwWallet Issuer',
		short_name: process.env.SITE_SHORT_NAME || 'wwWallet Issuer',
		theme_color: process.env.SITE_THEME_COLOR || '#00246b',
		background_color: process.env.SITE_BACKGROUND_COLOR || '#ffffff',
	},
	credentialOfferApiEnabled: process.env.CREDENTIAL_OFFER_API_ENABLED?.trim() === 'true',
	credentialOfferApiBearerToken: process.env.CREDENTIAL_OFFER_API_BEARER_TOKEN?.trim() || '',
	vctRegistryUrl: process.env.VCT_REGISTRY_URL || 'http://localhost:8097/type-metadata',
	vcClaimsFetcherEnabled: process.env.VC_CLAIMS_FETCHER_ENABLED?.trim() === 'true',
	vcClaimsFetcherUrl: process.env.VC_CLAIMS_FETCHER_URL || '',
	vcClaimsFetcherApiKey: process.env.VC_CLAIMS_FETCHER_API_KEY || '',
	supportedCredentialScopesWhitelist,
	revokeCredentialOffers: process.env.REVOKE_CREDENTIAL_OFFERS === 'true' || false,
	preAuthorizedCodeApiEnabled,
	preAuthorizedCodeApiBearerToken: process.env.PRE_AUTHORIZED_CODE_API_BEARER_TOKEN || '',
	preAuthorizedCodeTxCode: getTxCodeObject(),
	preAuthorizedCodeTxCodeLength: Number(process.env.PRE_AUTHORIZED_CODE_GRANT_LENGTH),
	preAuthorizedCodeAllowRefreshToken: process.env.PRE_AUTHORIZED_CODE_GRANT_REFRESH_TOKEN === 'true' || false,
	preAuthorizedCodeGrantTtlMs: Number(process.env.PRE_AUTHORIZED_CODE_GRANT_TTL_MS) || 60000
};

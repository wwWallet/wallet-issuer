import dotenv from 'dotenv';
dotenv.config({ quiet: true });

const url = String(process.env.SERVICE_URL || 'default_url');
const supportedCredentialScopesWhitelist = (process.env.SUPPORTED_CREDENTIAL_SCOPES_WHITELIST ?? '')
	.split(',')
	.map((scope) => scope.trim())
	.filter(Boolean);

export const config = {
	url: url,
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
	siteConfig: {
		name: process.env.SITE_NAME || 'wwWallet Issuer',
		short_name: process.env.SITE_SHORT_NAME || 'wwWallet Issuer',
		theme_color: process.env.SITE_THEME_COLOR || '#00246b',
		background_color: process.env.SITE_BACKGROUND_COLOR || '#ffffff',
	},
	vctRegistryUrl: process.env.VCT_REGISTRY_URL || 'http://localhost:8097/type-metadata',
	vcClaimsFetcherUrl: process.env.VC_CLAIMS_FETCHER_URL || '',
	vcClaimsFetcherApiKey: process.env.VC_CLAIMS_FETCHER_API_KEY || '',
	supportedCredentialScopesWhitelist,
	revokeCredentialOffers: process.env.REVOKE_CREDENTIAL_OFFERS === 'true' || false,
};

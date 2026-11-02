const baseLocale = {
	nav: {
		home: 'Home',
		about: 'About',
	},

	home: {
		title: 'Available credentials',
		subtitle: 'Select an authorization code type first, then choose a credential to continue.',
		empty: 'No credential configurations found.',
		issue: 'Start issuance',
		standardFlowTitle: 'Authorization Code',
		standardFlowDescription: 'Log in after returning to your Wallet',
		preAuthorizedFlowTitle: 'Pre-Authorized Code',
		preAuthorizedFlowDescription: 'Log in immediately',
		chooseFlow: 'Grant type',
	},

	offer: {
		back: 'Back',
		title: 'Add credential to your wallet',
		qrTitle: 'Scan QR',
		qrAlt: 'Credential offer QR code',
		pinInstruction: 'Use this PIN in your wallet:',
		openTitle: 'Open with',
		openInwwallet: 'wwWallet',
		openInGenericWallet: 'Other wallet',
		manualLabel: 'Offer link',
		authorizationCodeGrant: 'Authorization Code',
		preAuthorizedCodeGrant: 'Pre-Authorized Code',
		copy: 'Copy',
		copied: 'Copied',
	},

	error: {
		title: 'Error',
	},

	about: {
		subtitle: 'About this service',

		intro: `
The Demo wwWallet Issuer is a proof-of-concept service designed to issue
verifiable credentials (VCs) in SD-JWT or mdoc formats, supporting the
wwWallet ecosystem. It provides demonstrative credentials, including
Personal Identification (PID), European Health Insurance Card (EHIC),
Bachelor Diploma and Power of Representation VCs, strictly for testing
purposes (not valid for real-world use).
		`.trim(),

		issuerMetaPrefix: 'The issuer metadata is available at ',
		jwtMetaJoin: 'and the JWT VC Issuer Metadata configuration can be found at ',
		rootCaPrefix: "The Root CA certificate used to sign the issuer's certificate is available at ",

		openid4vciTitle: 'OpenID4VCI Interoperability Profile',
		openid4vpTitle: 'OpenID4VP Interoperability Profile',

		openid4vci: {
			spec: ['OIDVCI Specification', 'v1.0'],
			grant: [
				'Grant Type',
				'authorization_code [OpenID.Core], urn:ietf:params:oauth:grant-type:pre-authorized_code [OpenID4VCI]',
			],
			clientAuth: ['Client Authentication', 'PKCE [RFC 7636], no secret'],
			clientType: ['Client Type', 'Public'],
			dynamic: ['OpenID4VP, OAuth 2.0 for First-Party Applications'],
			scope: ['Scope', 'Required'],
			authMethod: ['Authorization Method', 'Pushed Authorization Request [RFC 9126]'],
			accessToken: ['Access Token', 'DPoP Token [RFC 9449]'],
			proof: ['Credential Endpoint Proof Type', 'jwt [OpenID4VCI]', 'Attestation'],
			binding: ['Credential Response Holder Binding', 'cnf claim [RFC 7800]'],
			batch: ['Batch Credential Endpoint', 'Supported'],
			deferred: ['Deferred Credential Endpoint', 'Supported'],
			notification: ['Notification Endpoint', 'Unsupported'],
			format: ['Credential Format', 'dc+sd-jwt, mso_mdoc'],
		},

		openid4vp: {
			spec: ['OIDVP Specification', 'v1.0'],
			responseMode: ['Response Mode', 'direct_post.jwt [OpenID4VP]'],
			requestMethod: ['Request Method', 'request_uri signed [JAR]'],
			clientId: ['Client ID Scheme', 'x509_san_dns, x509_hash'],
			format: ['Credential Format', 'dc+sd-jwt, mso_mdoc'],
		},
	},

	footer: {
		copyrightSuffix: 'wwWallet Issuer',
	},
};

export type DeepPartial<T> = {
	[P in keyof T]?: T[P] extends readonly unknown[]
		? T[P]
		: T[P] extends object
			? DeepPartial<T[P]>
			: T[P];
};

type LocalLocale = DeepPartial<Locale>;

const loadLocalLocale = (): LocalLocale => {
	let modulePath: string;
	try {
		modulePath = require.resolve('./locale.local');
	} catch (error) {
		if (
			typeof error === 'object' &&
			error !== null &&
			'code' in error &&
			error.code === 'MODULE_NOT_FOUND'
		) {
			return {};
		}
		throw error;
	}
	const localModule: unknown = require(modulePath);
	if (!isRecord(localModule) || !isRecord(localModule.locale)) {
		return {};
	}
	return localModule.locale as LocalLocale;
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
	typeof value === 'object' && value !== null && !Array.isArray(value);

const mergeLocale = <T extends Record<string, unknown>>(base: T, override: DeepPartial<T>): T => {
	const merged = { ...base } as Record<string, unknown>;

	for (const [key, value] of Object.entries(override)) {
		if (value === undefined) {
			continue;
		}

		const baseValue = merged[key];
		merged[key] = isRecord(baseValue) && isRecord(value) ? mergeLocale(baseValue, value) : value;
	}

	return merged as T;
};

export type Locale = typeof baseLocale;

export const locale = mergeLocale(baseLocale, loadLocalLocale());

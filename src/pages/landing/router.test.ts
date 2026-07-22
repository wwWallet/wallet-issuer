import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';

const { issuerMock, joseMock, dataStoreClientMock, storedOfferResults } = vi.hoisted(() => ({
	issuerMock: {
		getMetadata: vi.fn(),
		generateCredentialOffer: vi.fn(),
	},
	joseMock: {
		importJWK: vi.fn(),
		jwtVerify: vi.fn(),
	},
	dataStoreClientMock: {
		get: vi.fn(),
		set: vi.fn(),
	},
	storedOfferResults: new Map<string, { value: string; expiresAt?: number }>(),
}));

vi.mock('../../vci/issuer', () => ({
	issuer: issuerMock,
}));

vi.mock('jose', () => joseMock);

vi.mock('../../store/dataStoreClient', () => ({
	dataStoreClient: dataStoreClientMock,
}));

type RouteLayer = {
	route?: {
		path?: string;
		stack?: Array<{ handle: (req: any, res: any) => Promise<void> | void }>;
	};
};

const credentialConfigurationId = 'pid_sd_jwt';
const encodedCredentialConfigurationId = Buffer.from(credentialConfigurationId).toString('base64url');

const metadata = {
	credential_configurations_supported: {
		[credentialConfigurationId]: {
			scope: 'pid_scope',
			credential_metadata: {
				display: [{ name: 'PID' }],
			},
		},
	},
};

const loadLandingRouter = async (preAuthorizedCodeGrantTtlMs = 60000) => {
	vi.resetModules();
	vi.doMock('../../../config', () => ({
		config: {
			authorizationServerUrl: 'https://as.example',
			preAuthorizedCodeGrantClientId: 'wallet_issuer',
			preAuthorizedCodeGrantClientSecret: 'issuer-secret',
			preAuthorizedCodeGrantTtlMs,
			url: 'https://issuer.example',
			wwwalletURL: 'https://wallet.example/cb',
		},
	}));

	const { landingRouter } = await import('./router');
	return landingRouter as { stack: RouteLayer[] };
};

const getRouteHandlerFromRouter = (router: { stack: RouteLayer[] }, path: string) => {
	const route = router.stack.find((layer) => layer.route?.path === path)?.route;
	if (!route?.stack?.[0]?.handle) {
		throw new Error(`Route not found: ${path}`);
	}

	return route.stack[0].handle;
};

const getRouteHandler = async (path: string, preAuthorizedCodeGrantTtlMs?: number) => {
	const router = await loadLandingRouter(preAuthorizedCodeGrantTtlMs);
	return getRouteHandlerFromRouter(router, path);
};

const createResponse = () => {
	const response = {
		render: vi.fn(),
		redirect: vi.fn(),
	};

	return response;
};

const mockSuccessfulTokenFlow = () => {
	const tokenResponse = {
		id_token: 'eyJraWQiOiJraWQtMSIsImFsZyI6IlJTMjU2In0.payload.signature',
	};
	const discoveryResponse = {
		issuer: 'https://as.example',
		jwks_uri: 'https://as.example/jwks',
	};
	const jwksResponse = {
		keys: [{ kid: 'kid-1', alg: 'RS256', kty: 'RSA' }],
	};

	vi.stubGlobal('fetch', vi.fn()
		.mockResolvedValueOnce({
			json: vi.fn().mockResolvedValue(tokenResponse),
		})
		.mockResolvedValueOnce({
			ok: true,
			json: vi.fn().mockResolvedValue(discoveryResponse),
		})
		.mockResolvedValueOnce({
			ok: true,
			json: vi.fn().mockResolvedValue(jwksResponse),
		}));

	joseMock.importJWK.mockResolvedValue('public-key');
	joseMock.jwtVerify.mockResolvedValue({ payload: { sub: 'account-1' } });
};

describe('landingRouter pre-authorized offer flow', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		storedOfferResults.clear();
		vi.useRealTimers();
		dataStoreClientMock.set.mockImplementation(async (
			key: string,
			value: string,
			_mode?: string,
			ttlMs?: number,
		) => {
			storedOfferResults.set(key, {
				value,
				expiresAt: ttlMs === undefined ? undefined : Date.now() + ttlMs,
			});
			return 'OK';
		});
		dataStoreClientMock.get.mockImplementation(async (key: string) => {
			const storedResult = storedOfferResults.get(key);
			if (!storedResult || (storedResult.expiresAt !== undefined && storedResult.expiresAt <= Date.now())) {
				storedOfferResults.delete(key);
				return null;
			}

			return storedResult.value;
		});
		issuerMock.getMetadata.mockResolvedValue({ metadata });
		issuerMock.generateCredentialOffer.mockResolvedValue({
			credentialOfferWithReference: new URL(
				'https://issuer.example/offer?credential_offer_uri=https%3A%2F%2Fissuer.example%2Fopenid%2Fcredential-offer%2Fref-123',
			),
			txCode: '1234',
		});
	});

	afterEach(() => {
		vi.unstubAllGlobals();
		vi.useRealTimers();
	});

	it('registers the renamed initializer route and removes the temporary offer-result route', async () => {
		const router = await loadLandingRouter();
		const paths = router.stack.map((layer) => layer.route?.path).filter(Boolean);

		expect(paths).toContain('/initialize-pre-authorized-offer/:id');
		expect(paths).toContain('/pre-authorized-offer/:id');
		expect(paths).not.toContain('/offer-result/:id');
	});

	it('redirects the initializer route to the authorization server with credential state', async () => {
		const handler = await getRouteHandler('/initialize-pre-authorized-offer/:id');
		const res = createResponse();

		await handler({ params: { id: encodedCredentialConfigurationId } }, res);

		expect(res.redirect).toHaveBeenCalledOnce();
		const redirectUrl = new URL(res.redirect.mock.calls[0][0]);
		expect(`${redirectUrl.origin}${redirectUrl.pathname}`).toBe('https://as.example/auth');
		expect(redirectUrl.searchParams.get('client_id')).toBe('wallet_issuer');
		expect(redirectUrl.searchParams.get('response_type')).toBe('code');
		expect(redirectUrl.searchParams.get('scope')).toBe('openid pid_scope');
		expect(redirectUrl.searchParams.get('redirect_uri')).toBe('https://issuer.example/callback');
		expect(JSON.parse(redirectUrl.searchParams.get('state') ?? '{}')).toEqual({
			credential_configuration_id: credentialConfigurationId,
		});
	});

	it('stores callback result and redirects to the refreshable pre-authorized offer page', async () => {
		vi.setSystemTime(new Date('2026-07-03T10:00:00.000Z'));
		mockSuccessfulTokenFlow();
		const callbackHandler = await getRouteHandler('/callback');
		const res = createResponse();

		await callbackHandler({
			query: {
				code: 'authorization-code',
				state: JSON.stringify({ credential_configuration_id: credentialConfigurationId }),
			},
		}, res);

		expect(issuerMock.generateCredentialOffer).toHaveBeenCalledWith({
			credentialConfigurationId,
			grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
			accountId: 'account-1',
			scope: 'pid_scope',
		});
		expect(res.redirect).toHaveBeenCalledOnce();
		expect(res.redirect.mock.calls[0][0]).toBe(303);
		expect(res.redirect.mock.calls[0][1]).toMatch(/^\/pre-authorized-offer\/.+/);
		expect(dataStoreClientMock.set).toHaveBeenCalledWith(
			expect.stringMatching(/^landingPreAuthorizedOffer:.+/),
			expect.any(String),
			'PX',
			60000,
		);
	});

	it('renders the stored offer result while it has not expired', async () => {
		vi.setSystemTime(new Date('2026-07-03T10:00:00.000Z'));
		mockSuccessfulTokenFlow();
		const router = await loadLandingRouter();
		const callbackHandler = getRouteHandlerFromRouter(router, '/callback');
		const callbackRes = createResponse();

		await callbackHandler({
			query: {
				code: 'authorization-code',
				state: JSON.stringify({ credential_configuration_id: credentialConfigurationId }),
			},
		}, callbackRes);

		const resultPath = callbackRes.redirect.mock.calls[0][1] as string;
		const resultPathParts = resultPath.split('/');
		const resultId = resultPathParts[resultPathParts.length - 1];
		const offerHandler = getRouteHandlerFromRouter(router, '/pre-authorized-offer/:id');
		const offerRes = createResponse();

		await offerHandler({ params: { id: resultId } }, offerRes);

		expect(offerRes.render).toHaveBeenCalledWith('offer', expect.objectContaining({
			credentialName: 'PID',
			txCode: '1234',
			credentialOfferWithReference: expect.any(URL),
			credentialOfferWithReferenceForWwwallet: expect.any(URL),
		}));
	});

	it('rejects a stored offer result after preAuthorizedCodeGrantTtlMs expires', async () => {
		vi.setSystemTime(new Date('2026-07-03T10:00:00.000Z'));
		mockSuccessfulTokenFlow();
		const router = await loadLandingRouter(1000);
		const callbackHandler = getRouteHandlerFromRouter(router, '/callback');
		const callbackRes = createResponse();

		await callbackHandler({
			query: {
				code: 'authorization-code',
				state: JSON.stringify({ credential_configuration_id: credentialConfigurationId }),
			},
		}, callbackRes);

		const resultPath = callbackRes.redirect.mock.calls[0][1] as string;
		const resultPathParts = resultPath.split('/');
		const resultId = resultPathParts[resultPathParts.length - 1];
		const offerHandler = getRouteHandlerFromRouter(router, '/pre-authorized-offer/:id');
		const offerRes = createResponse();
		vi.setSystemTime(new Date('2026-07-03T10:00:01.001Z'));

		await offerHandler({ params: { id: resultId } }, offerRes);

		expect(offerRes.render).toHaveBeenCalledWith('error', {
			error: 'Invalid Credential Offer',
			errorDescription: 'This credential offer has expired or is no longer available. Please authenticate again to generate a new offer.',
		});
	});

	it.each([
		['malformed state', 'not-json'],
		['missing credential configuration', JSON.stringify({})],
	])('describes an invalid offer when callback state has %s', async (_scenario, state) => {
		mockSuccessfulTokenFlow();
		const callbackHandler = await getRouteHandler('/callback');
		const res = createResponse();

		await callbackHandler({ query: { code: 'authorization-code', state } }, res);

		expect(res.render).toHaveBeenCalledWith('error', {
			error: 'Invalid Credential Offer',
			errorDescription: 'We could not determine which credential to offer. Please return to the home page and try again.',
		});
	});

	it('describes an unavailable credential configuration returned in callback state', async () => {
		mockSuccessfulTokenFlow();
		const callbackHandler = await getRouteHandler('/callback');
		const res = createResponse();

		await callbackHandler({
			query: {
				code: 'authorization-code',
				state: JSON.stringify({ credential_configuration_id: 'unavailable' }),
			},
		}, res);

		expect(res.render).toHaveBeenCalledWith('error', {
			error: 'Invalid Credential Offer',
			errorDescription: 'The requested credential is not available. Please return to the home page and choose another credential.',
		});
	});
});

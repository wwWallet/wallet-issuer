import { describe, expect, it, vi } from 'vitest';

const { issuerMock } = vi.hoisted(() => ({
	issuerMock: {
		getMetadata: vi.fn(),
		generateCredentialOffer: vi.fn(),
		preAuthorizedCodeStore: {
			get: vi.fn(),
			delete: vi.fn(),
		},
	},
}));

vi.mock('../vci/issuer', () => ({
	issuer: issuerMock,
}));

type TestResponse = {
	statusCode: number;
	body: unknown;
};

const loadRouterModule = async (
	credentialOfferApiEnabled = false,
	credentialOfferApiBearerToken = 'test-token',
	preAuthorizedCodeApiEnabled = false,
	preAuthorizedCodeApiBearerToken = 'pre-auth-token',
) => {
	vi.resetModules();
	vi.doMock('../../config', () => ({
		config: {
			credentialOfferApiEnabled,
			credentialOfferApiBearerToken,
			preAuthorizedCodeApiEnabled,
			preAuthorizedCodeApiBearerToken,
		},
	}));

	const { createApiRouter, apiBearerAuth, preAuthorizedCodeApiBearerAuth } = await import('./router');

	return { createApiRouter, apiBearerAuth, preAuthorizedCodeApiBearerAuth };
};

const getRoute = (
	router: { stack: Array<{ route?: { path?: string; stack?: Array<{ name?: string }> } }> },
	path: string,
) => {
	return router.stack.find((layer) => layer.route?.path === path);
};

describe('API router configuration', () => {
	it('does not register any API routes when both APIs are disabled', async () => {
		const { createApiRouter } = await loadRouterModule(false, 'test-token', false, 'pre-auth-token');
		const router = createApiRouter();

		expect(getRoute(router, '/credential-offer-uri')).toBeUndefined();
		expect(getRoute(router, '/pre-authorized-code')).toBeUndefined();
	});

	it('registers the credential-offer and pre-authorized routes when enabled', async () => {
		const { createApiRouter } = await loadRouterModule(true, 'test-token', true, 'pre-auth-token');
		const router = createApiRouter();
		const credentialOfferRoute = getRoute(router, '/credential-offer-uri');
		const preAuthorizedCodeRoute = getRoute(router, '/pre-authorized-code');

		expect(credentialOfferRoute).toBeDefined();
		expect(preAuthorizedCodeRoute).toBeDefined();
		expect(credentialOfferRoute?.route?.stack?.some((layer: { name?: string }) => layer.name === 'apiBearerAuth')).toBe(true);
		expect(preAuthorizedCodeRoute?.route?.stack?.some((layer: { name?: string }) => layer.name === 'preAuthorizedCodeApiBearerAuth')).toBe(true);
	});

	it('throws when credential-offer API is enabled without a bearer token', async () => {
		await expect(loadRouterModule(true, '', false, 'pre-auth-token')).rejects.toThrow(
			'CREDENTIAL_OFFER_API_BEARER_TOKEN is required when CREDENTIAL_OFFER_API_ENABLED=true',
		);
	});

	it('throws when pre-authorized API is enabled without a bearer token', async () => {
		await expect(loadRouterModule(false, 'test-token', true, '')).rejects.toThrow(
			'PRE_AUTHORIZED_CODE_API_BEARER_TOKEN is required when PRE_AUTHORIZED_CODE_API_ENABLED=true',
		);
	});
});

describe('/api authentication', () => {
	const executeAuth = async (authorization?: string, type: 'credential-offer' | 'pre-authorized' = 'credential-offer') => {
		const { apiBearerAuth, preAuthorizedCodeApiBearerAuth } = await loadRouterModule(true, 'test-token', true, 'pre-auth-token');
		const response: TestResponse & { headers: Record<string, string> } = {
			statusCode: 0,
			body: undefined,
			headers: {},
		};
		const req = {
			get(name: string) {
				return name.toLowerCase() === 'authorization' ? authorization : undefined;
			},
		} as any;
		const res = {
			setHeader(name: string, value: string) {
				response.headers[name] = value;
			},
			status(code: number) {
				response.statusCode = code;
				return this;
			},
			send(payload: unknown) {
				response.body = payload;
				return this;
			},
		} as any;
		const next = vi.fn();

		(type === 'credential-offer' ? apiBearerAuth : preAuthorizedCodeApiBearerAuth)(req, res, next);
		return { response, next };
	};

	it('returns 401 when the credential-offer Authorization header is missing', async () => {
		const { response, next } = await executeAuth();

		expect(response.statusCode).toBe(401);
		expect(response.headers['WWW-Authenticate']).toBe('Bearer');
		expect(response.body).toEqual({
			error: 'unauthorized',
			error_description: 'Missing or invalid bearer token',
		});
		expect(next).not.toHaveBeenCalled();
	});

	it('continues for a valid credential-offer bearer token', async () => {
		const { response, next } = await executeAuth('Bearer test-token');

		expect(response.statusCode).toBe(0);
		expect(next).toHaveBeenCalledOnce();
	});

	it('continues for a valid pre-authorized bearer token', async () => {
		const { response, next } = await executeAuth('Bearer pre-auth-token', 'pre-authorized');

		expect(response.statusCode).toBe(0);
		expect(next).toHaveBeenCalledOnce();
	});
});

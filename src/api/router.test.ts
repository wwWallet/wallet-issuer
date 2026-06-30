import { beforeEach, describe, expect, it, vi } from 'vitest';

const { issuerMock } = vi.hoisted(() => ({
	issuerMock: {
		getMetadata: vi.fn(),
		generateCredentialOffer: vi.fn(),
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
) => {
	vi.resetModules();
	vi.doMock('../../config', () => ({
		config: {
			credentialOfferApiEnabled,
			credentialOfferApiBearerToken,
			preAuthorizedCodeApiEnabled: false,
		},
	}));

	const [{ createApiRouter, apiBearerAuth }, { credentialOfferUriHandler }] = await Promise.all([
		import('./router'),
		import('./credentialOfferUriHandler'),
	]);

	return { createApiRouter, apiBearerAuth, credentialOfferUriHandler };
};

const getCredentialOfferUriRoute = (router: { stack: Array<{ route?: { path?: string } }> }) => {
	return router.stack.find((layer) => layer.route?.path === '/credential-offer-uri');
};

const executeHandler = async (
	body: unknown,
	options: {
		credentialOfferApiEnabled?: boolean;
	} = {},
): Promise<TestResponse> => {
	const { credentialOfferUriHandler } = await loadRouterModule(options.credentialOfferApiEnabled ?? true);
	const response: TestResponse = {
		statusCode: 0,
		body: undefined,
	};

	const req = {
		body,
	} as any;
	const res = {
		status(code: number) {
			response.statusCode = code;
			return this;
		},
		send(payload: unknown) {
			response.body = payload;
			return this;
		},
	} as any;

	await credentialOfferUriHandler(req, res);
	return response;
};

describe('POST /api/credential-offer-uri configuration', () => {
	it('does not register the route when disabled', async () => {
		const { createApiRouter } = await loadRouterModule(false);
		const router = createApiRouter();

		expect(getCredentialOfferUriRoute(router)).toBeUndefined();
	});

	it('registers the route when enabled', async () => {
		const { createApiRouter } = await loadRouterModule(true);
		const router = createApiRouter();
		const routeLayer = router.stack.find((layer) => layer.route?.path === '/credential-offer-uri');

		expect(getCredentialOfferUriRoute(router)).toBeDefined();
		expect(routeLayer).toBeDefined();
		expect(routeLayer?.route?.stack.some((layer) => layer.name === 'apiBearerAuth')).toBe(true);
	});

	it('throws when enabled without a bearer token', async () => {
		await expect(loadRouterModule(true, '')).rejects.toThrow(
			'CREDENTIAL_OFFER_API_BEARER_TOKEN is required when CREDENTIAL_OFFER_API_ENABLED=true',
		);
	});
});

describe('/api authentication', () => {
	const executeAuth = async (authorization?: string) => {
		const { apiBearerAuth } = await loadRouterModule(true);
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

		apiBearerAuth(req, res, next);
		return { response, next };
	};

	it('returns 401 when the Authorization header is missing', async () => {
		const { response, next } = await executeAuth();

		expect(response.statusCode).toBe(401);
		expect(response.headers['WWW-Authenticate']).toBe('Bearer');
		expect(response.body).toEqual({
			error: 'unauthorized',
			error_description: 'Missing or invalid bearer token',
		});
		expect(next).not.toHaveBeenCalled();
	});

	it('returns 401 for an invalid bearer token', async () => {
		const { response, next } = await executeAuth('Bearer wrong-token');

		expect(response.statusCode).toBe(401);
		expect(next).not.toHaveBeenCalled();
	});

	it('continues for a valid bearer token', async () => {
		const { response, next } = await executeAuth('Bearer test-token');

		expect(response.statusCode).toBe(0);
		expect(next).toHaveBeenCalledOnce();
	});
});

describe('POST /api/credential-offer-uri input validation', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		issuerMock.getMetadata.mockResolvedValue({
			metadata: {
				credential_configurations_supported: {
					pid_sd_jwt: {},
				},
			},
		});
		issuerMock.generateCredentialOffer.mockResolvedValue({
			credentialOfferWithReference: new URL(
				'https://issuer.example/offer?credential_offer_uri=https%3A%2F%2Fissuer.example%2Fcredential-offer%2Fref-123',
			),
		});
	});

	it('returns 400 invalid_request when required fields are missing', async () => {
		const response = await executeHandler({});

		expect(response.statusCode).toBe(400);
		expect(response.body).toEqual({
			error: 'invalid_request',
			error_description: 'Missing or invalid parameters',
		});
	});

	it('returns 400 invalid_request when credential_configuration_ids is empty', async () => {
		const response = await executeHandler({
			credential_configuration_ids: [],
			grants: {
				authorization_code: { issuer_state: 'state-1' },
			},
		});

		expect(response.statusCode).toBe(400);
		expect(response.body).toEqual({
			error: 'invalid_request',
			error_description: 'Missing or invalid parameters',
		});
	});

	it('returns 501 unsupported_grant_type when authorization_code grant is missing', async () => {
		const response = await executeHandler({
			credential_configuration_ids: ['pid_sd_jwt'],
			grants: {
				'urn:ietf:params:oauth:grant-type:pre-authorized_code': {},
			},
		});

		expect(response.statusCode).toBe(501);
		expect(response.body).toEqual({
			error: 'unsupported_grant_type',
			error_description: 'Only authorization_code grant is supported',
		});
	});

	it('returns 501 unsupported_grant_type when extra grant types are included', async () => {
		const response = await executeHandler({
			credential_configuration_ids: ['pid_sd_jwt'],
			grants: {
				authorization_code: { issuer_state: 'state-1' },
				custom_grant: {},
			},
		});

		expect(response.statusCode).toBe(501);
		expect(response.body).toEqual({
			error: 'unsupported_grant_type',
			error_description: 'Only authorization_code grant is supported',
		});
	});

	it('returns 400 invalid_request when authorization_code payload is invalid', async () => {
		const response = await executeHandler({
			credential_configuration_ids: ['pid_sd_jwt'],
			grants: {
				authorization_code: { issuer_state: '' },
			},
		});

		expect(response.statusCode).toBe(400);
		expect(response.body).toEqual({
			error: 'invalid_request',
			error_description: 'Missing or invalid parameters',
		});
	});

	it('returns 400 invalid_request when authorization_code has extra fields', async () => {
		const response = await executeHandler({
			credential_configuration_ids: ['pid_sd_jwt'],
			grants: {
				authorization_code: {
					issuer_state: 'state-1',
					extra: 'not-allowed',
				},
			},
		});

		expect(response.statusCode).toBe(400);
		expect(response.body).toEqual({
			error: 'invalid_request',
			error_description: 'Missing or invalid parameters',
		});
	});

	it('returns 400 invalid_request for unsupported credential configuration id', async () => {
		const response = await executeHandler({
			credential_configuration_ids: ['unknown_credential'],
			grants: {
				authorization_code: { issuer_state: 'state-1' },
			},
		});

		expect(response.statusCode).toBe(400);
		expect(response.body).toEqual({
			error: 'invalid_request',
			error_description: 'Missing or invalid parameters',
		});
	});

	it('returns 201 and credential_offer_uri for valid input', async () => {
		const response = await executeHandler({
			credential_configuration_ids: ['pid_sd_jwt'],
			grants: {
				authorization_code: { issuer_state: 'state-1' },
			},
		});

		expect(response.statusCode).toBe(201);
		expect(response.body).toEqual({
			credential_offer_uri: 'https://issuer.example/credential-offer/ref-123',
		});
		expect(issuerMock.generateCredentialOffer).toHaveBeenCalledWith({
			credentialConfigurationId: 'pid_sd_jwt',
			grant_type: 'authorization_code',
			issuerState: 'state-1',
		});
	});
});

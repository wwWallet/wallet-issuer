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

const loadHandlerModule = async () => {
	vi.resetModules();
	vi.doMock('../../config', () => ({
		config: {
			credentialOfferApiEnabled: true,
			credentialOfferApiBearerToken: 'test-token',
			preAuthorizedCodeApiEnabled: false,
			preAuthorizedCodeApiBearerToken: 'pre-auth-token',
		},
	}));

	const { credentialOfferUriHandler } = await import('./credentialOfferUriHandler');
	return { credentialOfferUriHandler };
};

const executeHandler = async (body: unknown): Promise<TestResponse> => {
	const { credentialOfferUriHandler } = await loadHandlerModule();
	const response: TestResponse = {
		statusCode: 0,
		body: undefined,
	};

	const req = { body } as any;
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

describe('credentialOfferUriHandler', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		issuerMock.getMetadata.mockResolvedValue({
			metadata: {
				credential_configurations_supported: {
					pid_sd_jwt: { scope: 'pid:sd_jwt_dc' },
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

	it('returns 400 instead of silently ignoring additional credential configuration ids', async () => {
		const response = await executeHandler({
			credential_configuration_ids: ['pid_sd_jwt', 'another_credential'],
			grants: {
				authorization_code: { issuer_state: 'state-1' },
			},
		});

		expect(response.statusCode).toBe(400);
		expect(issuerMock.getMetadata).not.toHaveBeenCalled();
		expect(issuerMock.generateCredentialOffer).not.toHaveBeenCalled();
	});

	it('returns 400 when a pre-authorized_code grant has no account_id', async () => {
		const response = await executeHandler({
			credential_configuration_ids: ['pid_sd_jwt'],
			grants: {
				'urn:ietf:params:oauth:grant-type:pre-authorized_code': {},
			},
		});

		expect(response.statusCode).toBe(400);
		expect(response.body).toEqual({
			error: 'invalid_request',
			error_description: 'Missing or invalid parameters',
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
			error_description: 'Only authorization_code and pre-authorized_code grants are supported',
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
		expect(issuerMock.getMetadata).not.toHaveBeenCalled();
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

	it('creates a pre-authorized offer for the trusted API account_id', async () => {
		const response = await executeHandler({
			credential_configuration_ids: ['pid_sd_jwt'],
			grants: {
				'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
					account_id: 'api-account-1',
				},
			},
		});

		expect(response.statusCode).toBe(201);
		expect(issuerMock.generateCredentialOffer).toHaveBeenCalledWith({
			credentialConfigurationId: 'pid_sd_jwt',
			grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
			accountId: 'api-account-1',
			scope: 'pid:sd_jwt_dc',
		});
	});

	it('returns 500 when offer generation fails without exposing the internal error', async () => {
		issuerMock.generateCredentialOffer.mockRejectedValueOnce(new Error('sensitive internal failure'));

		const response = await executeHandler({
			credential_configuration_ids: ['pid_sd_jwt'],
			grants: {
				authorization_code: { issuer_state: 'state-1' },
			},
		});

		expect(response.statusCode).toBe(500);
		expect(response.body).toEqual({
			error: 'server_error',
			error_description: 'An unexpected error occurred',
		});
		expect(JSON.stringify(response.body)).not.toContain('sensitive internal failure');
	});

	it('returns 500 when the generated offer has no credential_offer_uri', async () => {
		issuerMock.generateCredentialOffer.mockResolvedValueOnce({
			credentialOfferWithReference: new URL('https://issuer.example/offer'),
		});

		const response = await executeHandler({
			credential_configuration_ids: ['pid_sd_jwt'],
			grants: {
				authorization_code: { issuer_state: 'state-1' },
			},
		});

		expect(response.statusCode).toBe(500);
		expect(response.body).toEqual({
			error: 'server_error',
			error_description: 'An unexpected error occurred',
		});
	});
});

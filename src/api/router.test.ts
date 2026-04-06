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

import { apiRouter } from './router';

type TestResponse = {
	statusCode: number;
	body: unknown;
};

const getCredentialOfferUriHandler = () => {
	const routeLayer = (apiRouter as any).stack.find((layer: any) => layer.route?.path === '/credential-offer-uri');
	if (!routeLayer) {
		throw new Error('Route /credential-offer-uri not found');
	}

	return routeLayer.route.stack[1].handle as (req: any, res: any) => Promise<unknown>;
};

const executeHandler = async (body: unknown): Promise<TestResponse> => {
	const handler = getCredentialOfferUriHandler();
	const response: TestResponse = {
		statusCode: 0,
		body: undefined,
	};

	const req = { body };
	const res = {
		status(code: number) {
			response.statusCode = code;
			return this;
		},
		send(payload: unknown) {
			response.body = payload;
			return this;
		},
	};

	await handler(req, res);
	return response;
};

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
			issuerState: 'state-1',
		});
	});
});

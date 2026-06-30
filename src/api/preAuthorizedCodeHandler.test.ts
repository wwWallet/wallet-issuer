import { beforeEach, describe, expect, it, vi } from 'vitest';

const { issuerMock } = vi.hoisted(() => ({
	issuerMock: {
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

const loadHandlerModule = async () => {
	vi.resetModules();
	vi.doMock('../../config', () => ({
		config: {
			credentialOfferApiEnabled: false,
			credentialOfferApiBearerToken: 'test-token',
			preAuthorizedCodeApiEnabled: true,
			preAuthorizedCodeApiBearerToken: 'pre-auth-token',
		},
	}));

	const { preAuthorizedCodeHandler } = await import('./preAuthorizedCodeHandler');
	return { preAuthorizedCodeHandler };
};

const executeHandler = async (body: unknown): Promise<TestResponse> => {
	const { preAuthorizedCodeHandler } = await loadHandlerModule();
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

	await preAuthorizedCodeHandler(req, res);
	return response;
};

describe('preAuthorizedCodeHandler', () => {
	beforeEach(() => {
		vi.clearAllMocks();
	});

	it('returns 400 invalid_request when required fields are missing', async () => {
		const response = await executeHandler({});

		expect(response.statusCode).toBe(400);
		expect(response.body).toEqual({
			error: 'invalid_request',
			error_description: 'Missing or invalid parameters',
		});
	});

	it('returns 400 invalid_grant when the grant is missing', async () => {
		issuerMock.preAuthorizedCodeStore.get.mockResolvedValue(undefined);

		const response = await executeHandler({
			'pre-authorized_code': 'missing-code',
		});

		expect(response.statusCode).toBe(400);
		expect(response.body).toEqual({
			error: 'invalid_grant',
			error_description: 'Missing or already consumed grant.',
		});
	});

	it('returns 200 and deletes the grant for a valid request', async () => {
		issuerMock.preAuthorizedCodeStore.get.mockResolvedValue({
			tx_code: true,
			tx_value: '12345',
			credential_configuration_ids: ['pid_sd_jwt'],
		});

		const response = await executeHandler({
			'pre-authorized_code': 'valid-code',
			tx_code: '12345',
		});

		expect(response.statusCode).toBe(200);
		expect(response.body).toEqual({
			tx_code: true,
			tx_value: '12345',
			credential_configuration_ids: ['pid_sd_jwt'],
		});
		expect(issuerMock.preAuthorizedCodeStore.delete).toHaveBeenCalledWith('valid-code');
	});
});

import { beforeEach, describe, expect, it, vi } from 'vitest';

const { issuerMock } = vi.hoisted(() => ({
	issuerMock: {
		preAuthorizedCodeStore: {
			consume: vi.fn(),
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
		issuerMock.preAuthorizedCodeStore.consume.mockResolvedValue(undefined);

		const response = await executeHandler({
			'pre-authorized_code': 'missing-code',
		});

		expect(response.statusCode).toBe(400);
		expect(response.body).toEqual({
			error: 'invalid_grant',
			error_description: 'Missing or already consumed grant.',
		});
	});

	it('returns 200 for a valid atomically consumed grant', async () => {
		issuerMock.preAuthorizedCodeStore.consume.mockResolvedValue({
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
		expect(issuerMock.preAuthorizedCodeStore.consume).toHaveBeenCalledWith('valid-code');
	});

	it('rejects a wrong tx_code after atomically consuming the grant', async () => {
		issuerMock.preAuthorizedCodeStore.consume.mockResolvedValue({
			tx_code: true,
			tx_value: '12345',
			credential_configuration_ids: ['pid_sd_jwt'],
		});

		const response = await executeHandler({
			'pre-authorized_code': 'single-attempt-code',
			tx_code: '54321',
		});

		expect(response.statusCode).toBe(400);
		expect(response.body).toEqual({
			error: 'invalid_grant',
			error_description: 'Invalid tx_code.',
		});
		expect(issuerMock.preAuthorizedCodeStore.consume).toHaveBeenCalledWith('single-attempt-code');
	});

	it('allows only one of two concurrent requests to consume a grant', async () => {
		const grant = {
			credential_configuration_ids: ['pid_sd_jwt'],
		};
		issuerMock.preAuthorizedCodeStore.consume
			.mockResolvedValueOnce(grant)
			.mockResolvedValueOnce(undefined);

		const [firstResponse, secondResponse] = await Promise.all([
			executeHandler({ 'pre-authorized_code': 'single-use-code' }),
			executeHandler({ 'pre-authorized_code': 'single-use-code' }),
		]);

		expect([firstResponse.statusCode, secondResponse.statusCode].sort()).toEqual([200, 400]);
		expect(issuerMock.preAuthorizedCodeStore.consume).toHaveBeenCalledTimes(2);
	});
});

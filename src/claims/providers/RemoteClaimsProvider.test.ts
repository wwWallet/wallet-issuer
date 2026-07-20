import { afterEach, describe, expect, it, vi } from 'vitest';
import { RemoteClaimsProvider } from './RemoteClaimsProvider';

describe('RemoteClaimsProvider', () => {
	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('fetches claims using only the opaque subject', async () => {
		const fetchMock = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({ data: { family_name: 'Example' } }),
		});
		vi.stubGlobal('fetch', fetchMock);

		const provider = new RemoteClaimsProvider('https://esc.example/claims', {
			supportedScopes: ['pid:sd_jwt_dc'],
		});
		const result = await provider.resolveClaims('opaque-issuance-reference', 'pid:sd_jwt_dc');

		expect(result.kind).toBe('ready');
		expect(fetchMock).toHaveBeenCalledOnce();
		const request = fetchMock.mock.calls[0][1] as RequestInit;
		expect(JSON.parse(String(request.body))).toEqual({
			data: { sub: 'opaque-issuance-reference' },
		});
	});

	it('uses the master issuer_state field name when it is available', async () => {
		const fetchMock = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({ data: { family_name: 'Example' } }),
		});
		vi.stubGlobal('fetch', fetchMock);

		const provider = new RemoteClaimsProvider('https://esc.example/claims', {
			supportedScopes: ['pid:sd_jwt_dc'],
		});
		await provider.resolveClaims('authenticated-subject', 'pid:sd_jwt_dc', {
			issuerState: 'opaque-issuer-state',
		});

		const request = fetchMock.mock.calls[0][1] as RequestInit;
		expect(JSON.parse(String(request.body))).toEqual({
			data: {
				sub: 'authenticated-subject',
				issuer_state: 'opaque-issuer-state',
			},
		});
	});
});

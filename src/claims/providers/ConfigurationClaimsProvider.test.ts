import { afterEach, describe, expect, it, vi } from 'vitest';
import { ConfigurationClaimsProvider } from './ConfigurationClaimsProvider';
import { ClaimsProvider } from '../ClaimsProvider';

const filesystemProvider: ClaimsProvider = {
	async resolveAccountId(sub) {
		return sub === 'test' ? sub : null;
	},
	async resolveClaims() {
		return { kind: 'ready', claims: { source: 'filesystem' } };
	},
};

describe('ConfigurationClaimsProvider', () => {
	afterEach(() => vi.restoreAllMocks());

	it('routes different credential configurations to filesystem and remote sources', async () => {
		const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
			data: { family_name: 'Remote' },
		}), { status: 200, headers: { 'content-type': 'application/json' } }));
		const provider = new ConfigurationClaimsProvider({
			'pid:sd_jwt_dc': {
				type: 'remote',
				url: 'https://pid.example/claims',
				apiKey: 'pid-secret',
			},
		}, filesystemProvider);

		expect(await provider.resolveAccountId('test')).toBe('test');
		expect(await provider.resolveAccountId('opaque-remote-subject')).toBe('opaque-remote-subject');
		expect(await provider.resolveClaims('opaque-remote-subject', 'pid:sd_jwt_dc')).toEqual({
			kind: 'ready',
			claims: { vct: 'urn:eudi:pid:1', family_name: 'Remote' },
		});
		expect(fetchMock).toHaveBeenCalledOnce();
		expect(fetchMock.mock.calls[0][0].toString()).toBe('https://pid.example/claims');
		expect(new Headers(fetchMock.mock.calls[0][1]?.headers).get('x-api-key')).toBe('pid-secret');

		const filesystemResult = await provider.resolveClaims('test', 'diploma');
		expect(filesystemResult).toEqual({ kind: 'ready', claims: { source: 'filesystem' } });
		expect(fetchMock).toHaveBeenCalledOnce();
	});

	it('uses the filesystem account lookup when no remote source is configured', async () => {
		const provider = new ConfigurationClaimsProvider({}, filesystemProvider);
		expect(await provider.resolveAccountId('test')).toBe('test');
		expect(await provider.resolveAccountId('missing')).toBeNull();
	});

	it('fails at startup when a remote URL is missing or invalid', () => {
		expect(() => new ConfigurationClaimsProvider({
			'pid:sd_jwt_dc': { type: 'remote', url: '' },
		}, filesystemProvider)).toThrow("Invalid remote claims URL for scope 'pid:sd_jwt_dc'");
	});
});

import express from 'express';
import { afterEach, describe, expect, it, vi } from 'vitest';

const { issuerMock } = vi.hoisted(() => ({ issuerMock: { issueCredential: vi.fn() } }));
vi.mock('./issuer', () => ({ issuer: issuerMock }));
vi.mock('fs', async (importOriginal) => { const actual = await importOriginal<typeof import('fs')>(); return { ...actual, default: { ...actual, readFileSync: () => '' }, readFileSync: () => '' }; });

describe('VCI credential endpoint request parsing', () => {
	afterEach(() => vi.clearAllMocks());
	it('passes an application/jwt request body to the issuer as text', async () => {
		issuerMock.issueCredential.mockResolvedValue({ status: 200, headers: { 'content-type': 'application/json' }, data: { credential: 'ok' } });
		const { vciRouter } = await import('./router');
		const app = express().use(vciRouter);
		const server = await new Promise<ReturnType<typeof app.listen>>((resolve) => resolve(app.listen(0)));
		try {
			const address = server.address();
			if (!address || typeof address === 'string') throw new Error('server did not bind');
			const response = await fetch('http://127.0.0.1:' + address.port + '/credential', { method: 'POST', headers: { 'content-type': 'application/jwt' }, body: 'encrypted-request' });
			expect(response.status).toBe(200);
			expect(issuerMock.issueCredential).toHaveBeenCalledWith({ request: { headers: expect.objectContaining({ 'content-type': 'application/jwt' }), data: 'encrypted-request' } });
		} finally {
			await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
		}
	});
});

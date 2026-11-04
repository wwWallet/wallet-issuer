import { describe, expect, it, vi } from 'vitest';
import { SDJwtInstance } from '@sd-jwt/core';
import { digest } from '@sd-jwt/crypto-nodejs';

vi.mock('fs', () => ({
	default: {
		readFileSync: vi.fn((filePath: string) =>
			filePath.endsWith('pem.crt')
				? '-----BEGIN CERTIFICATE-----\nY2VydA==\n-----END CERTIFICATE-----'
				: 'test-private-key',
		),
	},
}));

vi.mock('crypto', async (importOriginal) => {
	const actual = await importOriginal<typeof import('crypto')>();
	return {
		...actual,
		sign: vi.fn(() => Buffer.from('test-signature')),
	};
});

vi.mock('jose', () => ({
	calculateJwkThumbprint: vi.fn().mockResolvedValue('holder-thumbprint'),
	exportJWK: vi.fn().mockResolvedValue({ kty: 'EC', crv: 'P-256', x: 'x', y: 'y' }),
	importX509: vi.fn().mockResolvedValue({}),
}));

vi.mock('./util/importPrivateKeyPem', () => ({
	importPrivateKeyPem: vi.fn().mockResolvedValue({}),
}));

vi.mock('../config/vctDocumentProvider', () => ({
	vctDocumentProvider: {
		getVctMetadataDocument: vi.fn().mockResolvedValue({ ok: false }),
	},
}));

const decodeBase64UrlJson = (encoded: string): Record<string, unknown> | unknown[] =>
	JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));

describe('signSdJwtVc', () => {
	it('issues selective, nested, and plaintext claims according to the disclosure frame', async () => {
		const { signer } = await import('./signer.js');
		const claims = {
			vct: 'urn:test:signing',
			family_name: 'Doe',
			issuing_country: 'GR',
			place_of_birth: {
				country: 'GR',
				region: 'Attica',
				locality: 'Athens',
			},
			address: {
				country: 'GR',
				street: {
					name: 'Example Street',
					house_number: '10',
				},
			},
			age_equal_or_over: {
				'18': true,
				'21': false,
			},
			cnf: { jwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' } },
		};
		const disclosureFrame = {
			family_name: true,
			issuing_country: false,
			place_of_birth: {
				country: true,
				region: false,
				locality: true,
			},
			address: {
				country: true,
				street: {
					name: true,
					house_number: false,
				},
			},
			age_equal_or_over: {
				'18': true,
				'21': false,
			},
		};

		const { credential } = await signer.signSdJwtVc(claims, {}, disclosureFrame);

		const [encodedJwt, ...encodedDisclosuresWithTerminator] = credential.split('~');
		const [encodedHeader, encodedPayload] = encodedJwt.split('.');
		const header = decodeBase64UrlJson(encodedHeader) as Record<string, unknown>;
		const payload = decodeBase64UrlJson(encodedPayload) as Record<string, unknown>;
		const encodedDisclosures = encodedDisclosuresWithTerminator.filter(Boolean);
		const disclosureKeys = encodedDisclosures
			.map((encoded) => decodeBase64UrlJson(encoded) as unknown[])
			.map((disclosure) => disclosure[1])
			.sort();
		const reconstructedClaims = await new SDJwtInstance({ hasher: digest }).getClaims(credential);

		expect(header).toMatchObject({ typ: 'dc+sd-jwt', alg: 'ES256', x5c: expect.any(Array) });
		expect(header.x5c).toHaveLength(1);
		expect(payload).toMatchObject({
			vct: 'urn:test:signing',
			issuing_country: 'GR',
			_sd_alg: 'sha-256',
			place_of_birth: {
				region: 'Attica',
				_sd: expect.any(Array),
			},
			address: {
				_sd: expect.any(Array),
				street: {
					house_number: '10',
					_sd: expect.any(Array),
				},
			},
			age_equal_or_over: {
				'21': false,
				_sd: expect.any(Array),
			},
		});
		expect(payload).not.toHaveProperty('family_name');
		expect(payload).not.toHaveProperty('place_of_birth.country');
		expect(payload).not.toHaveProperty('place_of_birth.locality');
		expect(payload).not.toHaveProperty('address.country');
		expect(payload).not.toHaveProperty('address.street.name');
		expect(payload).not.toHaveProperty('age_equal_or_over.18');
		expect(payload._sd).toHaveLength(1);
		expect(payload).toHaveProperty('place_of_birth._sd', [expect.any(String), expect.any(String)]);
		expect(payload).toHaveProperty('address._sd', [expect.any(String)]);
		expect(payload).toHaveProperty('address.street._sd', [expect.any(String)]);
		expect(payload).toHaveProperty('age_equal_or_over._sd', [expect.any(String)]);
		expect(disclosureKeys).toEqual(['18', 'country', 'country', 'family_name', 'locality', 'name']);
		expect(reconstructedClaims).toMatchObject(claims);
	});
});

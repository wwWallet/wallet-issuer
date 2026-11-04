import { describe, expect, it } from 'vitest';
import { TypeMetadata } from 'wallet-common';
import { SDJwtInstance, type DisclosureFrame as CoreDisclosureFrame } from '@sd-jwt/core';
import { digest } from '@sd-jwt/crypto-nodejs';
import { createDisclosureFrame } from './createDisclosureFrame';

describe('createDisclosureFrame', () => {
	it('creates a native disclosure frame from Type Metadata', () => {
		const payload = {
			family_name: 'Doe',
			issuing_country: 'GR',
			address: { country: 'GR', locality: 'Athens' },
			nationalities: ['GR', 'DE'],
		};
		const typeMetadata: TypeMetadata = {
			vct: 'urn:test',
			claims: [
				{ path: ['family_name'], sd: 'always' },
				{ path: ['issuing_country'], sd: 'never' },
				{ path: ['address', 'country'], sd: 'always' },
				{ path: ['address', 'locality'] },
				{ path: ['nationalities', null], sd: 'allowed' },
				{ path: ['missing'], sd: 'always' },
			],
		};

		expect(createDisclosureFrame(payload, typeMetadata)).toEqual({
			_sd: ['family_name'],
			address: { _sd: ['country', 'locality'] },
			nationalities: { _sd: [0, 1] },
		});
	});

	it('discloses a whole array with all of its elements', async () => {
		const payload = { nationalities: ['US', 'GR'] };
		const typeMetadata: TypeMetadata = {
			vct: 'urn:test',
			claims: [
				{ path: ['nationalities', null], sd: 'never' },
				{ path: ['nationalities'], sd: 'always' },
			],
		};
		const disclosureFrame = createDisclosureFrame(payload, typeMetadata);
		let salt = 0;
		const sdJwt = new SDJwtInstance({
			signer: async () => Buffer.from('signature').toString('base64url'),
			hasher: digest,
			hashAlg: 'sha-256',
			signAlg: 'ES256',
			saltGenerator: () => `salt-${salt++}`,
		});

		const credential = await sdJwt.issue(
			payload,
			disclosureFrame as CoreDisclosureFrame<typeof payload>,
		);
		const presentation = await sdJwt.present<{ nationalities: string[] }>(credential, {
			nationalities: true,
		});

		expect(disclosureFrame).toEqual({ _sd: ['nationalities'] });
		await expect(sdJwt.getClaims(presentation)).resolves.toEqual(payload);
	});
});

import { describe, expect, it } from 'vitest';
import { TypeMetadata } from 'wallet-common';
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
});

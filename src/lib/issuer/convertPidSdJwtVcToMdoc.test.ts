import { describe, expect, it } from 'vitest';
import { convertPidSdJwtVcToMdoc } from './convertPidSdJwtVcToMdoc';

describe('convertPidSdJwtVcToMdoc', () => {
	it('converts the PID picture data URL to an mdoc portrait byte string', () => {
		const result = convertPidSdJwtVcToMdoc({ picture: 'data:image/jpeg;base64,/9j/AA==' });
		expect(result.portrait).toEqual(new Uint8Array([0xff, 0xd8, 0xff, 0x00]));
	});

	it('does not put malformed or unsupported picture values into the mdoc', () => {
		expect(convertPidSdJwtVcToMdoc({ picture: 'https://example.com/photo.jpg' }).portrait).toBeUndefined();
		expect(convertPidSdJwtVcToMdoc({ picture: 'data:image/svg+xml;base64,PHN2Zz4=' }).portrait).toBeUndefined();
		expect(convertPidSdJwtVcToMdoc({ picture: 'data:image/jpeg;base64,ZmFrZQ==' }).portrait).toBeUndefined();
	});
});

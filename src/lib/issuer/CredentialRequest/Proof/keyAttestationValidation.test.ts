import { deflateSync } from 'node:zlib';
import { describe, expect, it, vi } from 'vitest';
import {
	decodeStatusListEntry,
	validateKeyAttestationAssurance,
	validateKeyAttestationStatus,
} from './keyAttestationValidation';

describe('key attestation validation', () => {
	it('accepts any assurance value allowed by issuer metadata', () => {
		expect(validateKeyAttestationAssurance({
			key_storage: ['iso_18045_high'],
			user_authentication: ['iso_18045_moderate'],
		}, {
			key_storage: ['iso_18045_moderate', 'iso_18045_high'],
			user_authentication: ['iso_18045_moderate'],
		})).toBeNull();
	});

	it('rejects missing or unacceptable assurance claims', () => {
		expect(validateKeyAttestationAssurance({}, {
			key_storage: ['iso_18045_high'],
		})).toMatch(/key_storage/);
		expect(validateKeyAttestationAssurance({
			key_storage: ['iso_18045_basic'],
		}, {
			key_storage: ['iso_18045_high'],
		})).toMatch(/key_storage/);
	});

	it('decodes valid and revoked one-bit status list entries', () => {
		const bytes = Buffer.alloc(2);
		bytes[1] |= 1 << 1; // index 9
		const payload = {
			status_list: {
				bits: 1,
				lst: deflateSync(bytes).toString('base64url'),
			},
		};

		expect(decodeStatusListEntry(payload, 8)).toBe(false);
		expect(decodeStatusListEntry(payload, 9)).toBe(true);
	});

	it('rejects an expired storage-status reference without fetching it', async () => {
		const fetchStatusList = vi.fn();
		await expect(validateKeyAttestationStatus({
			key_storage_status: {
				exp: Math.floor(Date.now() / 1000) - 1,
				status: { status_list: { idx: 0, uri: 'https://wallet.example/status' } },
			},
		}, [], { fetchStatusList })).resolves.toMatch(/expired/);
		expect(fetchStatusList).not.toHaveBeenCalled();
	});
});

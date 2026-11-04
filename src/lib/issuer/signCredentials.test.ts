import { afterEach, describe, expect, it, vi } from 'vitest';
import { OpenidCredentialIssuerMetadata, VerifiableCredentialFormat } from 'wallet-common';
import { JWK } from 'jose';
import { logger } from '../../logger';
import { CredentialRequestErrors } from './CredentialRequest/CredentialRequestError';
import { CredentialIssuerCreateOptions } from './IssuerOpenID4VCI';
import { PlainIssueCredentialRequestOptions } from './IssuerOpenID4VCITypes';
import { signCredentials } from './signCredentials';

describe('signCredentials', () => {
	afterEach(() => vi.restoreAllMocks());

	it.each([
		{ name: 'single issuance', keys: [] },
		{ name: 'batch issuance', keys: [{ kty: 'EC' }, { kty: 'EC' }] as JWK[] },
	])('returns an internal error when $name signing fails', async ({ keys }) => {
		const signingError = new Error('private registry details');
		const signSdJwtVc = vi.fn().mockRejectedValue(signingError);
		const loggerError = vi.spyOn(logger, 'error').mockImplementation(() => logger);
		const metadata = {
			credential_configurations_supported: {
				test: {
					format: VerifiableCredentialFormat.DC_SDJWT,
					scope: 'test',
					vct: 'urn:test',
				},
			},
		} as unknown as OpenidCredentialIssuerMetadata;

		const result = await signCredentials(
			'test',
			metadata,
			{ sub: 'subject', vct: 'urn:test' },
			keys,
			{} as PlainIssueCredentialRequestOptions,
			{ credentialSigner: { signSdJwtVc } } as unknown as CredentialIssuerCreateOptions,
		);

		expect(result).toEqual({
			ok: false,
			error: CredentialRequestErrors.InternalServerError,
			error_description: 'Credential signing failed',
		});
		expect(result.ok ? '' : result.error_description).not.toContain(signingError.message);
		expect(loggerError).toHaveBeenCalledWith('Credential signing failed', {
			error: signingError,
		});
	});
});

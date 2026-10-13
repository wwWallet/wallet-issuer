import { describe, expect, it, vi } from 'vitest';
import { JWK } from 'jose';
import { VerifiableCredentialFormat } from 'wallet-common';
import { CredentialRequestErrors } from './CredentialRequest/CredentialRequestError';
import { signCredentials } from './signCredentials';

const holderJwk: JWK = {
	kty: 'EC',
	crv: 'P-256',
	x: 'nUWAoAv3XZith8E7i19OdaxOLYFOwM-Z2EuM02TirT4',
	y: 'HskHU8BjUi1U9Xqi7Swmj8gwAK_0xkcDjEW_71SosEY',
};

const createOptions = () => {
	const signSdJwtVc = vi.fn().mockResolvedValue({ credential: 'signed-sd-jwt' });
	const signMsoMdoc = vi.fn().mockResolvedValue({ credential: 'signed-mdoc' });
	return {
		signSdJwtVc,
		signMsoMdoc,
		options: {
			credentialSigner: { signSdJwtVc, signMsoMdoc },
		} as any,
	};
};

const requestWithoutProofs = {
	request: {
		headers: { 'content-type': 'application/json', authorization: 'Bearer token', dpop: 'dpop' },
		data: { credential_configuration_id: 'pid' },
	},
} as any;

const requestWithProofs = {
	request: {
		headers: { 'content-type': 'application/json', authorization: 'Bearer token', dpop: 'dpop' },
		data: { credential_configuration_id: 'pid', proofs: { jwt: ['proof-jwt'] } },
	},
} as any;

describe('signCredentials', () => {
	it('binds a dc+sd-jwt credential to the verified holder key', async () => {
		const { options, signSdJwtVc } = createOptions();
		const disclosureFrame = { family_name: true };
		const metadata = {
			credential_configurations_supported: {
				pid: { format: VerifiableCredentialFormat.DC_SDJWT, scope: 'pid', vct: 'urn:eudi:pid:1' },
			},
		} as any;

		const result = await signCredentials('pid', metadata, { sub: 'subject', vct: 'urn:eudi:pid:1', family_name: 'Doe' }, [holderJwk], new Map([['pid', disclosureFrame]]), requestWithProofs, options);

		expect(result).toEqual({ ok: true, value: ['signed-sd-jwt'] });
		expect(signSdJwtVc).toHaveBeenCalledWith(
			{ sub: 'subject', vct: 'urn:eudi:pid:1', family_name: 'Doe', cnf: { jwk: holderJwk } },
			{},
			disclosureFrame,
		);
	});

	it('returns invalid_proof instead of calling the SD-JWT signer without cnf.jwk when no proofs were provided', async () => {
		const { options, signSdJwtVc } = createOptions();
		const metadata = {
			credential_configurations_supported: {
				diploma: { format: VerifiableCredentialFormat.DC_SDJWT, scope: 'diploma', vct: 'urn:credential:diploma' },
			},
		} as any;

		const result = await signCredentials('diploma', metadata, { sub: 'subject', vct: 'urn:credential:diploma' }, [], new Map(), requestWithoutProofs, options);

		expect(result).toMatchObject({ ok: false, error: CredentialRequestErrors.InvalidProof });
		expect(signSdJwtVc).not.toHaveBeenCalled();
	});

	it('returns invalid_proof instead of calling the SD-JWT signer without cnf.jwk when proofs produced no holder key', async () => {
		const { options, signSdJwtVc } = createOptions();
		const metadata = {
			credential_configurations_supported: {
				pid: { format: VerifiableCredentialFormat.DC_SDJWT, scope: 'pid', vct: 'urn:eudi:pid:1' },
			},
		} as any;

		const result = await signCredentials('pid', metadata, { sub: 'subject', vct: 'urn:eudi:pid:1' }, [], new Map(), requestWithProofs, options);

		expect(result).toMatchObject({ ok: false, error: CredentialRequestErrors.InvalidProof });
		expect(signSdJwtVc).not.toHaveBeenCalled();
	});
});

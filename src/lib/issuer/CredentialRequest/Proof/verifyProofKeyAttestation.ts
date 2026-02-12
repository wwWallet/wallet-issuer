// OpenID4VCI D.1. Key Attestation in JWT format
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-key-attestation-in-jwt-form

import { err, ok, Result, fromBase64Url, verifyX5C } from 'wallet-common';
import { CredentialRequestError, CredentialRequestErrors } from '../CredentialRequestError';
import { importJWK, importX509, JWK, jwtVerify } from 'jose';
import { VerifyProofOptions } from './verifyProof';

export async function verifyProofKeyAttestation(attestation: string, options: VerifyProofOptions): Promise<Result<{ attested_keys: JWK[] }, CredentialRequestError>> {
	const dec = new TextDecoder();
	const [attestationHeader, attestationPayload] = attestation.split('.');
	const [parsedHeader, parsedPayload] = [JSON.parse(dec.decode(fromBase64Url(attestationHeader))), JSON.parse(dec.decode(fromBase64Url(attestationPayload)))] as [Record<string, unknown>, Record<string, unknown>];

	if (!parsedHeader.typ || typeof parsedHeader.typ !== 'string' || parsedHeader.typ !== 'key-attestation+jwt') {
		return err(CredentialRequestErrors.InvalidProof, "Wrong key attestation header. Expected 'key-attestation+jwt'");
	}

	if (!parsedHeader.alg || typeof parsedHeader.alg !== 'string') {
		return err(CredentialRequestErrors.InvalidProof, "Wrong key attestation header. 'alg' is missing");
	}

	if (options.expectedNonce && (!parsedPayload.nonce || typeof parsedPayload.nonce !== 'string' || options.expectedNonce !== parsedPayload.nonce)) {
		return err(CredentialRequestErrors.InvalidNonce, 'Wrong key attestation payload. Invalid nonce.');
	}

	// verify attestation signature using JWS 'x5c' header
	if (options.requiredVerificationMechanisms.includes('x5c')) {
		if (parsedHeader.x5c && parsedHeader.x5c instanceof Array && typeof parsedHeader.alg === 'string') {
			const certs = await options.getAllTrustedPemCertificates();
			const result = await verifyX5C(parsedHeader.x5c, certs);
			if (!result) {
				return err(CredentialRequestErrors.CredentialRequestDenied, "key attestation could not be verified with this certificate in the 'x5c' header");
			}
			const leafCertPem = `-----BEGIN CERTIFICATE-----
				${parsedHeader.x5c[0].match(/.{1,64}/g).join('\n')}
			-----END CERTIFICATE-----`;
			const publicKey = await importX509(leafCertPem, parsedHeader.alg);
			try {
				await jwtVerify(attestation, publicKey, { clockTolerance: options.clockTolerance });
			} catch {
				return err(CredentialRequestErrors.InvalidProof, 'key attestation signature is invalid');
			}
		} else {
			return err(CredentialRequestErrors.CredentialRequestDenied, "'x5c' header missing from key attestation");
		}
	}

	// verify validity of 'attested_keys' payload attribute
	if (!('attested_keys' in parsedPayload) || !(parsedPayload.attested_keys instanceof Array) || parsedPayload.attested_keys.length === 0) {
		return err(CredentialRequestErrors.InvalidProof, "Key attestation cannot have missing or empty 'attested_keys' payload attribute");
	}
	try {
		await Promise.all(parsedPayload.attested_keys.map((jwk: JWK) => importJWK(jwk, jwk.alg ?? 'ES256')));
	} catch {
		return err(CredentialRequestErrors.InvalidProof, 'Invalid Key attestation: At least one of the attested_keys is invalid');
	}

	return ok({ attested_keys: parsedPayload.attested_keys as JWK[] });
}

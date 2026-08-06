// OpenID4VCI D.1. Key Attestation in JWT format
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-key-attestation-in-jwt-form

import { err, ok, Result, fromBase64Url, verifyX5C } from 'wallet-common';
import { CredentialRequestError, CredentialRequestErrors } from '../CredentialRequestError';
import { importJWK, importX509, JWK, jwtVerify } from 'jose';
import { VerifyProofOptions } from './verifyProof';
import { validateKeyAttestationAssurance, validateKeyAttestationStatus } from './keyAttestationValidation';

export async function verifyProofKeyAttestation(attestation: string, options: VerifyProofOptions, nonceRequired: boolean = false): Promise<Result<{ attested_keys: JWK[] }, CredentialRequestError>> {
	let parsedHeader: Record<string, unknown>;
	let parsedPayload: Record<string, unknown>;
	try {
		const dec = new TextDecoder();
		const [attestationHeader, attestationPayload] = attestation.split('.');
		[parsedHeader, parsedPayload] = [JSON.parse(dec.decode(fromBase64Url(attestationHeader))), JSON.parse(dec.decode(fromBase64Url(attestationPayload)))] as [Record<string, unknown>, Record<string, unknown>];
	}
	catch {
		return err(CredentialRequestErrors.InvalidProof, 'Key attestation is not a valid JWT');
	}

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
				const verified = await jwtVerify(attestation, publicKey, {
					algorithms: [parsedHeader.alg],
					clockTolerance: options.clockTolerance,
				});
				parsedPayload = verified.payload;
			} catch {
				return err(CredentialRequestErrors.InvalidProof, 'key attestation signature is invalid');
			}
		} else {
			return err(CredentialRequestErrors.CredentialRequestDenied, "'x5c' header missing from key attestation");
		}
	}
	if (nonceRequired) {
		if (typeof parsedPayload.nonce !== 'string') {
			return err(CredentialRequestErrors.InvalidNonce, 'Key attestation is missing a nonce');
		}
		if (options.verifyNonce && !await options.verifyNonce(parsedPayload.nonce)) {
			return err(CredentialRequestErrors.InvalidNonce, 'Key attestation contains an invalid or expired nonce');
		}
	}

	const assuranceError = validateKeyAttestationAssurance(parsedPayload, options.keyAttestationRequirements);
	if (assuranceError) {
		return err(CredentialRequestErrors.CredentialRequestDenied, assuranceError);
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

	const statusError = await validateKeyAttestationStatus(
		parsedPayload,
		await options.getAllTrustedPemCertificates(),
	);
	if (statusError) {
		return err(CredentialRequestErrors.CredentialRequestDenied, statusError);
	}

	return ok({ attested_keys: parsedPayload.attested_keys as JWK[] });
}

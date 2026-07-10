// OpenID4VCI F.1. jwt Proof Type
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-jwt-proof-type

import { exportJWK, importJWK, importX509, JWK, jwtVerify } from 'jose';
import { err, ok, Result, fromBase64Url, verifyX5C } from 'wallet-common';
import { CredentialRequestError, CredentialRequestErrors } from '../CredentialRequestError';
import { verifyProofKeyAttestation } from './verifyProofKeyAttestation';
import { VerifyProofOptions } from './verifyProof';

export async function verifyProofJwt(jwt: string, options: VerifyProofOptions): Promise<Result<{ attested_keys: JWK[] }, CredentialRequestError>> {
	let parsedHeader: Record<string, unknown>;
	let parsedPayload: Record<string, unknown>;
	try {
		const dec = new TextDecoder();
		const [encodedHeader, encodedPayload, signature, ...extraParts] = jwt.split('.');
		if (!encodedHeader || !encodedPayload || !signature || extraParts.length) {
			return err(CredentialRequestErrors.InvalidProof, 'proof jwt is malformed');
		}
		[parsedHeader, parsedPayload] = [JSON.parse(dec.decode(fromBase64Url(encodedHeader))), JSON.parse(dec.decode(fromBase64Url(encodedPayload)))] as [Record<string, unknown>, Record<string, unknown>];
	} catch {
		return err(CredentialRequestErrors.InvalidProof, 'proof jwt is malformed');
	}

	if (!parsedHeader.typ || typeof parsedHeader.typ !== 'string' || parsedHeader.typ !== 'openid4vci-proof+jwt') {
		return err(CredentialRequestErrors.InvalidProof, "Wrong proof jwt header. Expected 'openid4vci-proof+jwt'");
	}

	if (!parsedHeader.alg || typeof parsedHeader.alg !== 'string') {
		return err(CredentialRequestErrors.InvalidProof, "Wrong proof jwt header. 'alg' is missing");
	}
	if (parsedHeader.alg !== 'ES256') {
		return err(CredentialRequestErrors.InvalidProof, "Unsupported proof jwt algorithm. Expected 'ES256'");
	}

	if (options.expectedNonce && (!parsedPayload.nonce || typeof parsedPayload.nonce !== 'string' || options.expectedNonce !== parsedPayload.nonce)) {
		return err(CredentialRequestErrors.InvalidNonce, 'Wrong proof jwt payload. Invalid nonce.');
	}
	const keyIdentifierCount = Number(parsedHeader.jwk !== undefined) + Number(parsedHeader.x5c !== undefined) + Number(parsedHeader.kid !== undefined);
	if (keyIdentifierCount !== 1) {
		return err(CredentialRequestErrors.InvalidProof, "proof jwt must contain exactly one of 'jwk', 'x5c', or 'kid'");
	}

	const verifyWithHolderKey = async (holderJwk: JWK): Promise<Result<{ attested_keys: JWK[] }, CredentialRequestError>> => {
		if (holderJwk.d) {
			return err(CredentialRequestErrors.InvalidProof, 'proof jwt holder key must be public');
		}

		try {
			const publicKey = await importJWK(holderJwk, 'ES256');
			const { payload } = await jwtVerify(jwt, publicKey, {
				algorithms: ['ES256'],
				audience: options.credentialIssuerIdentifier,
				clockTolerance: options.clockTolerance,
				requiredClaims: ['aud', 'iat', 'nonce'],
			});
			if (typeof payload.nonce !== 'string') {
				return err(CredentialRequestErrors.InvalidNonce, "missing 'nonce' from payload of jwt proof");
			}
			if (options.verifyNonce && !(await options.verifyNonce(payload.nonce))) {
				return err(CredentialRequestErrors.InvalidNonce, 'proof jwt contains an invalid or expired nonce');
			}
			return ok({ attested_keys: [holderJwk] });
		} catch {
			return err(CredentialRequestErrors.InvalidProof, 'proof jwt signature is invalid');
		}
	};

	if (parsedHeader.jwk && typeof parsedHeader.jwk === 'object') {
		return verifyWithHolderKey(parsedHeader.jwk as JWK);
	} else if (parsedHeader.x5c instanceof Array) {
		try {
			if (!parsedHeader.x5c.length || parsedHeader.x5c.some((certificate) => typeof certificate !== 'string')) {
				return err(CredentialRequestErrors.InvalidProof, "proof jwt 'x5c' header is malformed");
			}
			const certificateChain = parsedHeader.x5c as string[];
			const trustedCertificates = await options.getAllTrustedPemCertificates();
			if (!(await verifyX5C(certificateChain, trustedCertificates))) {
				return err(CredentialRequestErrors.InvalidProof, "proof jwt 'x5c' certificate chain is not trusted");
			}
			const leafCertificatePem = `-----BEGIN CERTIFICATE-----\n${certificateChain[0].match(/.{1,64}/g)?.join('\n')}\n-----END CERTIFICATE-----`;
			const leafPublicKey = await importX509(leafCertificatePem, 'ES256');
			const holderJwk = await exportJWK(leafPublicKey);
			return verifyWithHolderKey(holderJwk);
		} catch {
			return err(CredentialRequestErrors.InvalidProof, "proof jwt 'x5c' header could not be verified");
		}
	} else if (typeof parsedHeader.kid === 'string') {
		if (typeof parsedHeader.key_attestation === 'string') {
			const keyAttestationResult = await verifyProofKeyAttestation(parsedHeader.key_attestation, options);
			if (!keyAttestationResult.ok) {
				return keyAttestationResult;
			}
			const keyIndex = Number(parsedHeader.kid);
			if (!Number.isSafeInteger(keyIndex) || keyIndex < 0 || keyIndex >= keyAttestationResult.value.attested_keys.length) {
				return err(CredentialRequestErrors.InvalidProof, "proof jwt 'kid' does not identify a key in the key attestation");
			}
			const proofResult = await verifyWithHolderKey(keyAttestationResult.value.attested_keys[keyIndex]);
			return proofResult.ok ? keyAttestationResult : proofResult;
		}
		if (!options.resolveKid) {
			return err(CredentialRequestErrors.InvalidProof, "proof jwt uses 'kid', but no trusted kid resolver is configured");
		}
		try {
			const holderJwk = await options.resolveKid(parsedHeader.kid);
			if (!holderJwk) {
				return err(CredentialRequestErrors.InvalidProof, "proof jwt 'kid' could not be resolved");
			}
			return verifyWithHolderKey(holderJwk);
		} catch {
			return err(CredentialRequestErrors.InvalidProof, "proof jwt 'kid' could not be resolved");
		}
	} else {
		return err(CredentialRequestErrors.InvalidProof, "proof jwt must identify its signing key with 'jwk', 'x5c', or 'kid'");
	}
}

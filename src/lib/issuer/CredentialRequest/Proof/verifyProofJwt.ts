// OpenID4VCI F.1. jwt Proof Type
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-jwt-proof-type

import { importJWK, importX509, JWK, jwtVerify } from "jose";
import { err, ok, Result } from "../../../core/Result";
import { CredentialRequestError, CredentialRequestErrors } from "../CredentialRequestError";
import { fromBase64Url } from "wallet-common/dist/utils/util";
import { verifyX5C } from "wallet-common";
import { verifyProofKeyAttestation } from "./verifyProofKeyAttestation";
import { VerifyProofOptions } from "./verifyProof";

export async function verifyProofJwt(jwt: string, options: VerifyProofOptions): Promise<Result<{ attested_keys: JWK[] }, CredentialRequestError>> {

	const dec = new TextDecoder();
	const [attestationHeader, attestationPayload,] = jwt.split('.');
	const [parsedHeader, parsedPayload] = [
		JSON.parse(dec.decode(fromBase64Url(attestationHeader))),
		JSON.parse(dec.decode(fromBase64Url(attestationPayload))),
	] as [Record<string, unknown>, Record<string, unknown>];


	const attestedKeys: JWK[] = [];

	if (!parsedHeader.typ || typeof parsedHeader.typ !== 'string' || parsedHeader.typ !== "openid4vci-proof+jwt") {
		return err(CredentialRequestErrors.InvalidProof, "Wrong proof jwt header. Expected 'openid4vci-proof+jwt'")
	}

	if (!parsedHeader.alg || typeof parsedHeader.alg !== 'string') {
		return err(CredentialRequestErrors.InvalidProof, "Wrong proof jwt header. 'alg' is missing");
	}

	if (options.expectedNonce && (!parsedPayload.nonce ||
		typeof parsedPayload.nonce !== 'string' ||
		options.expectedNonce !== parsedPayload.nonce)) {

		return err(CredentialRequestErrors.InvalidNonce, "Wrong proof jwt payload. Invalid nonce.");
	}

	if (parsedHeader.jwk) {
		const publicKey = await importJWK(parsedHeader.jwk);
		try {
			const { payload, protectedHeader } = await jwtVerify(jwt, publicKey, { clockTolerance: options.clockTolerance });
			if (protectedHeader.jwk) {
				attestedKeys.push(protectedHeader.jwk);
			}
			if (!payload.nonce) {
				return err(CredentialRequestErrors.InvalidProof, "missing 'nonce' from payload of jwt proof");
			}
			if (options.expectedNonce && payload.nonce !== options.expectedNonce) {
				return err(CredentialRequestErrors.InvalidProof, "invalid 'nonce' on payload of jwt proof");
			}
		}
		catch {
			return err(CredentialRequestErrors.InvalidProof, "proof jwt signature is invalid");
		}
	}
	else if (parsedHeader.x5c && parsedHeader.x5c instanceof Array) {
		const certs = await options.getAllTrustedPemCertificates();
		const result = await verifyX5C(parsedHeader.x5c, certs);
		if (!result) {
			return err(CredentialRequestErrors.CredentialRequestDenied, "proof jwt could not be verified with this certificate in the 'x5c' header");
		}
		const leafCertPem = `-----BEGIN CERTIFICATE-----
			${parsedHeader.x5c[0].match(/.{1,64}/g).join('\n')}
		-----END CERTIFICATE-----`;
		const publicKey = await importX509(leafCertPem, parsedHeader.alg);
		try {
			const { payload } = await jwtVerify(jwt, publicKey, { clockTolerance: options.clockTolerance, audience: options.credentialIssuerIdentifier });
			if (!payload.nonce) {
				return err(CredentialRequestErrors.InvalidProof, "missing 'nonce' from payload of jwt proof");
			}
			if (options.expectedNonce && payload.nonce !== options.expectedNonce) {
				return err(CredentialRequestErrors.InvalidProof, "invalid 'nonce' on payload of jwt proof");
			}
		}
		catch {
			return err(CredentialRequestErrors.InvalidProof, "proof jwt signature is invalid");
		}
	}

	if (parsedHeader.key_attestation && typeof parsedHeader.key_attestation === 'string') {
		return verifyProofKeyAttestation(parsedHeader.key_attestation, options);
	}

	return ok({ attested_keys: attestedKeys });
}

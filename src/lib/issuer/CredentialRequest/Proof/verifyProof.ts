import { JWK } from "jose";
import { err, ok, Result } from "../../../core/Result";
import { CredentialRequestError, CredentialRequestErrors } from "../CredentialRequestError";
import { verifyProofJwt } from "./verifyProofJwt";
import { verifyProofKeyAttestation } from "./verifyProofKeyAttestation";

export type VerifyProofOptions = {
	getAllTrustedPemCertificates: () => Promise<string[]>,
	requiredVerificationMechanisms: ("x5c" | "jwk" | "kid")[],
	expectedNonce?: string,
	cliend_id?: string,
	credentialIssuerIdentifier: string,
	clockTolerance?: number,
}

export async function verifyProof(proof: { jwt: string } | { attestation: string }, options: VerifyProofOptions): Promise<Result<{ attested_keys: JWK[] }, CredentialRequestError>> {

	if ('attestation' in proof) {
		return verifyProofKeyAttestation(proof.attestation, options);
	}
	else if ('jwt' in proof) {
		return verifyProofJwt(proof.jwt, options);
	}
	return err(CredentialRequestErrors.InvalidRequest, "Proof object does not include 'jwt' or 'attestation' JSON attribute");
}

export async function verifyProofsWrapper(proofs: ({ jwt: string } | { attestation: string })[], options: VerifyProofOptions): Promise<Result<{ attested_keys: JWK[] }, CredentialRequestError>> {

	const verifyProofResults = await Promise.all(
		proofs.map(async (proof) => {
			return verifyProof(proof, options);
		})
	);
	// if at least one error detected, reject the whole request
	for (const res of verifyProofResults) {
		if (!res.ok) {
			return res;
		}
	}

	const attestedKeys = verifyProofResults
		.reduce((acc, val) => val.ok ? acc.concat(val.value.attested_keys) : acc, [] as JWK[]);
	return ok({ attested_keys: attestedKeys });
}

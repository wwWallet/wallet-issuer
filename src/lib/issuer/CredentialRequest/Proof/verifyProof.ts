import { JWK } from "jose";
import { err, ok, Result } from "wallet-common";
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


export async function verifyProofsWrapper(proofs: ({ jwt: string[] } | { attestation: string[] }), options: VerifyProofOptions): Promise<Result<{ attested_keys: JWK[] }, CredentialRequestError>> {
	const verifyProofResults = await (async () => {
		if ('jwt' in proofs) {
			return Promise.all(
				proofs.jwt.map(async (proof) =>
					verifyProofJwt(proof, options)
				)
			);
		}
		else if ('attestation' in proofs) {
			return Promise.all(
				proofs.attestation.map(async (proof) =>
					verifyProofKeyAttestation(proof, options)
				)
			);
		}
		return undefined;
	})();

	if (!verifyProofResults) {
		return err(CredentialRequestErrors.InvalidProof, "'proofs' object does not contain neither 'jwt' nor 'attestation' key");
	}

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

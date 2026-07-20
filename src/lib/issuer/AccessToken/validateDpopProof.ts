import { createHash } from 'node:crypto';
import { ok, err, Result } from 'wallet-common';
import { CredentialRequestError, CredentialRequestErrors } from '../CredentialRequest/CredentialRequestError';
import { calculateJwkThumbprint, EmbeddedJWK, errors as JoseErrors, JWK, jwtVerify } from 'jose';
import type { UniqueStore } from '../../../store/DataStore';

const DPOP_SIGNING_ALG_VALUES = ['ES256'];
const DPOP_PROOF_MAX_AGE_SECONDS = 300;

export type ValidateDpopProofOptions = {
	method: string;
	htu: string;
	accessToken: string;
	clockTolerance?: number;
	replayStore: UniqueStore<string, string>;
};

/**
 *
 * @param dpopJwt
 * @param cnf The object returned from the introspection endpoint
 * @returns
 */
export async function validateDpopProof(dpopJwt: string, cnf: { jkt?: string } | undefined, options: ValidateDpopProofOptions): Promise<Result<null, CredentialRequestError>> {
	const fail = (description: string) => err(CredentialRequestErrors.InvalidRequest, description);

	if (!cnf?.jkt) {
		return fail("Introspection response does not contain 'cnf.jkt'");
	}

	if (!dpopJwt) {
		return fail('DPoP proof is missing');
	}

	const clockTolerance = options.clockTolerance ?? 0;

	try {
		const { protectedHeader, payload } = await jwtVerify(dpopJwt, EmbeddedJWK, {
			algorithms: DPOP_SIGNING_ALG_VALUES,
			typ: 'dpop+jwt',
		});

		if (protectedHeader.typ !== 'dpop+jwt') {
			return fail('DPoP proof typ must be dpop+jwt');
		}

		const jwk = protectedHeader.jwk as JWK | undefined;
		if (!jwk) {
			return fail('DPoP proof must include a public jwk header');
		}

		if ('d' in jwk || 'k' in jwk) {
			return fail('DPoP proof jwk must not contain private or symmetric key material');
		}

		if (protectedHeader.alg !== 'ES256') {
			return fail('DPoP proof alg must be ES256');
		}

		if (jwk.alg !== undefined && jwk.alg !== 'ES256') {
			return fail('DPoP proof jwk alg must be ES256 when present');
		}

		const calculatedJkt = await calculateJwkThumbprint(jwk);
		if (calculatedJkt !== cnf.jkt) {
			return fail('DPoP bound public key has different JWK thumbprint from cnf.jkt received from the authorization server');
		}

		if (payload.htm !== options.method.toUpperCase()) {
			return fail('DPoP proof htm mismatch');
		}

		if (typeof payload.htu !== 'string') {
			return fail('DPoP proof htu must be a string');
		}

		if (normalizeHtu(payload.htu) !== normalizeHtu(options.htu)) {
			return fail('DPoP proof htu mismatch');
		}

		if (payload.ath !== calculateAth(options.accessToken)) {
			return fail('DPoP proof ath mismatch');
		}

		if (typeof payload.iat !== 'number' || !Number.isInteger(payload.iat)) {
			return fail('DPoP proof must have an integer iat claim');
		}

		const now = Math.floor(Date.now() / 1000);
		if (payload.iat > now + clockTolerance) {
			return fail('DPoP proof iat is in the future');
		}

		if (now - payload.iat > DPOP_PROOF_MAX_AGE_SECONDS + clockTolerance) {
			return fail('DPoP proof iat is not recent enough');
		}

		if (typeof payload.jti !== 'string' || payload.jti.length === 0) {
			return fail('DPoP proof must have a non-empty jti claim');
		}

		const replayMarkerTtlMs = Math.max(
			1,
			(payload.iat + DPOP_PROOF_MAX_AGE_SECONDS + clockTolerance + 1) * 1000 - Date.now(),
		);
		let replayMarkerCreated: boolean;
		try {
			replayMarkerCreated = await markReplayStoreUnique(options.replayStore, calculatedJkt, payload.jti, replayMarkerTtlMs);
		} catch {
			return err(CredentialRequestErrors.InternalServerError, 'Could not check DPoP proof replay state');
		}
		if (!replayMarkerCreated) {
			return fail('DPoP proof replay detected');
		}

		return ok(null);
	} catch (error) {
		if (error instanceof TypeError && error.message.includes('Invalid URL')) {
			return fail('DPoP proof htu is not a valid URL');
		}

		if (error instanceof JoseErrors.JOSEError) {
			return fail(`Invalid DPoP proof: ${error.message}`);
		}

		return fail('Invalid DPoP proof');
	}
}

function calculateAth(accessToken: string): string {
	return createHash('sha256')
		.update(accessToken)
		.digest('base64url');
}

function normalizeHtu(htu: string): string {
	const url = new URL(htu);
	url.hash = '';
	url.search = '';
	return url.href;
}

async function markReplayStoreUnique(replayStore: UniqueStore<string, string>, jkt: string, jti: string, ttlMs: number): Promise<boolean> {
	const key = createHash('sha256')
		.update(jkt)
		.update('\0')
		.update(jti)
		.digest('base64url');
	return replayStore.setIfAbsent(key, '1', ttlMs);
}

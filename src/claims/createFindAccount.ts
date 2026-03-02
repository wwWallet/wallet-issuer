import { FindAccount } from '../lib/issuer/Account/FindAccount';
import { createClaimsFuture } from '../lib/issuer/ClaimsFuture';
import { CredentialRequestErrors } from '../lib/issuer/CredentialRequest/CredentialRequestError';
import { err, ok } from 'wallet-common';
import { ClaimsProvider } from './ClaimsProvider';

export const createFindAccount = (claimsProvider: ClaimsProvider): FindAccount => {
	return async (ctx, sub, _token) => {
		const accountId = await claimsProvider.resolveAccountId(sub);
		if (!accountId) {
			return undefined;
		}

		return {
			accountId,
			async claims(_use, scope, _claims) {
				if (ctx.request.transactionId) {
					const claimsFutures = await ctx.credentialRequestHelper.getCredentialRequests(ctx.request.transactionId);
					if (claimsFutures[0]) {
						return ok(claimsFutures[0]);
					}
				}

				const claimsResult = await claimsProvider.resolveClaims(accountId, scope);
				if (claimsResult.kind === 'denied') {
					return err(CredentialRequestErrors.CredentialRequestDenied, claimsResult.reason);
				}
				if (claimsResult.kind === 'pending') {
					return ok(await ctx.credentialRequestHelper.submitCredentialRequest({ sub: accountId, scope }));
				}

				return ok(createClaimsFuture<{ sub: string;[key: string]: unknown }>(accountId, scope, {
					claims: {
						sub: accountId,
						...claimsResult.claims,
					},
				}));
			},
		};
	};
};

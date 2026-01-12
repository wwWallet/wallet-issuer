import { FindAccount } from "../src/lib/issuer/Account/FindAccount";
import fs from 'node:fs/promises';
import path from 'path';
import { createClaimsFuture } from "../src/lib/issuer/CredentialRequestHelper";

type AccountEntry = {
	id: string;
	pid: Record<string, unknown>;
	diploma: Record<string, unknown>;
	ehic: Record<string, unknown>;
	por: Record<string, unknown>;
};

const getAccountEntryById = async (id: string): Promise<AccountEntry | null> => {
	const data = await fs.readFile(path.join(__dirname, "../../dataset/accounts.json"), 'utf-8');
	const parsedData = JSON.parse(data.toString());
	return parsedData.accounts.filter((r: AccountEntry) => r.id === id)[0] ?? null;
}


export const findAccount: FindAccount = async (ctx, sub, _token) => {

	const acc = await getAccountEntryById(sub);
	if (!acc) {
		return undefined;
	}


	return {
		accountId: acc.id,
		async claims(_use, scope, _claims) {
			if (ctx.request.transactionId) {
				const claimsFuture = await ctx.credentialRequestHelper.getCredentialRequest(ctx.request.transactionId);
				if (claimsFuture) {
					return claimsFuture;
				}
			}


			if (scope.split(' ').includes('por:sd_jwt_vc:deferred')) {
				return ctx.credentialRequestHelper.submitCredentialRequest({ sub: acc.id, scope: scope });
			}
			let releasedClaims = { };
			if (scope.split(' ').includes('pid:sd_jwt_dc') || scope.split(' ').includes('pid:mso_mdoc')) {
				releasedClaims = { ...acc.pid };
			}
			if (scope.split(' ').includes('ehic')) {
				releasedClaims = { ...releasedClaims, ...acc.ehic };
			}
			if (scope.split(' ').includes('diploma')) {
				releasedClaims = { ...releasedClaims, ...acc.diploma };
			}
			if (scope.split(' ').includes('por:sd_jwt_vc')) {
				releasedClaims = { ...releasedClaims, ...acc.por };
			}

			return createClaimsFuture<{ sub: string, [key: string]: unknown }>({
				claims: {
			    	sub: acc.id,
					...releasedClaims,
				},
			});
		},
	};
}

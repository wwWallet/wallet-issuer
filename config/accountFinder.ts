import { FindAccount } from "../src/lib/issuer/Account/FindAccount";
import fs from 'node:fs/promises';
import path from 'path';
import { createClaimsFuture } from "../src/lib/issuer/CredentialRequestHelper";
import { supportedCredentialConfigurations } from "./supportedCredentialConfigurations";

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

const findSupportedCredentialByScope = (scope: string) => {
	const result = Object.entries(supportedCredentialConfigurations).filter(([_k, v]) => v.scope === scope)[0];
	if (!result) {
		return null;
	}
	const [_credentialConfigurationId, credentialConfiguration] = result;
	return credentialConfiguration;
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
				const supportedConf = findSupportedCredentialByScope('pid:sd_jwt_dc');
				let claimsToRelease = {};
				if (supportedConf && 'vct' in supportedConf) {
					claimsToRelease = { vct: supportedConf.vct };
				}
				return ctx.credentialRequestHelper.submitCredentialRequest({ sub: acc.id, scope: scope, ...claimsToRelease });
			}
			let releasedClaims = { };
			if (scope.split(' ').includes('pid:sd_jwt_dc') || scope.split(' ').includes('pid:mso_mdoc')) {
				const supportedConf = findSupportedCredentialByScope('pid:sd_jwt_dc');
				if (supportedConf && 'vct' in supportedConf) {
					releasedClaims = { ...releasedClaims, vct: supportedConf.vct };
				}
				releasedClaims = { ...releasedClaims, ...acc.pid};
			}
			if (scope.split(' ').includes('ehic')) {
				const supportedConf = findSupportedCredentialByScope('ehic');
				if (supportedConf && 'vct' in supportedConf) {
					releasedClaims = { ...releasedClaims, vct: supportedConf.vct };
				}
				releasedClaims = { ...releasedClaims, ...acc.ehic };
			}
			if (scope.split(' ').includes('diploma')) {
				const supportedConf = findSupportedCredentialByScope('diploma');
				if (supportedConf && 'vct' in supportedConf) {
					releasedClaims = { ...releasedClaims, vct: supportedConf.vct };
				}
				releasedClaims = { ...releasedClaims, ...acc.diploma };
			}
			if (scope.split(' ').includes('por:sd_jwt_vc')) {
				const supportedConf = findSupportedCredentialByScope('por:sd_jwt_vc');
				if (supportedConf && 'vct' in supportedConf) {
					releasedClaims = { ...releasedClaims, vct: supportedConf.vct };
				}
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

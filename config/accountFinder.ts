import { FindAccount } from '../src/lib/issuer/Account/FindAccount';
import fs from 'node:fs/promises';
import path from 'path';
import { createClaimsFuture } from '../src/lib/issuer/CredentialRequestHelper';
import { supportedCredentialConfigurations } from './supportedCredentialConfigurations';
import { credentialRequestHelper } from '../src/vci/issuer';
import { convertPidSdJwtVcToMdoc } from '../src/lib/issuer/convertPidSdJwtVcToMdoc';
import { err, ok } from 'wallet-common';
import { CredentialRequestErrors } from '../src/lib/issuer/CredentialRequest/CredentialRequestError';

type AccountEntry = {
	id: string;
	pid: Record<string, unknown>;
	diploma: Record<string, unknown>;
	ehic: Record<string, unknown>;
	por: Record<string, unknown>;
};

const getAccountEntryById = async (id: string): Promise<AccountEntry | null> => {
	const data = await fs.readFile(path.join(__dirname, '../../dataset/accounts.json'), 'utf-8');
	const parsedData = JSON.parse(data.toString());
	return parsedData.accounts.filter((r: AccountEntry) => r.id === id)[0] ?? null;
};

const findSupportedCredentialByScope = (scope: string) => {
	const result = Object.entries(supportedCredentialConfigurations).filter(([_k, v]) => v.scope === scope)[0];
	if (!result) {
		return null;
	}
	const [_credentialConfigurationId, credentialConfiguration] = result;
	return credentialConfiguration;
};

export const findAccount: FindAccount = async (ctx, sub, _token) => {
	const acc = await getAccountEntryById(sub);
	if (!acc) {
		return undefined;
	}

	return {
		accountId: acc.id,
		async claims(_use, scope, _claims) {
			if (ctx.request.transactionId) {
				const claimsFutures = await ctx.credentialRequestHelper.getCredentialRequests(ctx.request.transactionId);
				if (claimsFutures[0]) {
					return ok(claimsFutures[0]);
				}
			}

			let releasedClaims = {};
			if (scope.split(' ').includes('por:sd_jwt_vc')) {
				// submit credential request for later approval
				return ok(await ctx.credentialRequestHelper.submitCredentialRequest({ sub: acc.id, scope: scope }));
			}
			else if (scope.split(' ').includes('pid:sd_jwt_dc')) {
				const supportedConf = findSupportedCredentialByScope('pid:sd_jwt_dc');
				if (supportedConf && 'vct' in supportedConf) {
					releasedClaims = { ...releasedClaims, vct: supportedConf.vct };
				}
				releasedClaims = { ...releasedClaims, ...acc.pid };
			}
			else if (scope.split(' ').includes('pid:mso_mdoc')) {
				const pidMdoc = convertPidSdJwtVcToMdoc(acc.pid);
				releasedClaims = { ...pidMdoc };
			}
			else if (scope.split(' ').includes('ehic')) {
				const supportedConf = findSupportedCredentialByScope('ehic');
				if (supportedConf && 'vct' in supportedConf) {
					releasedClaims = { ...releasedClaims, vct: supportedConf.vct };
				}
				releasedClaims = { ...releasedClaims, ...acc.ehic };
			}
			else if (scope.split(' ').includes('diploma')) {
				const supportedConf = findSupportedCredentialByScope('diploma');
				if (supportedConf && 'vct' in supportedConf) {
					releasedClaims = { ...releasedClaims, vct: supportedConf.vct };
				}
				releasedClaims = { ...releasedClaims, ...acc.diploma };
			}
			else {
				return err(CredentialRequestErrors.CredentialRequestDenied, "Not supported scope");
			}

			return ok(createClaimsFuture<{ sub: string;[key: string]: unknown }>(acc.id, scope, {
				claims: {
					sub: acc.id,
					...releasedClaims,
				},
			}));
		},
	};
};

let loopRunning = false;

/**
 *
 * This loop will be used to auto-fullfil the POR Deferred Credential Requests to
 * simulate asynchronous credential issuance.
 */
async function runLoop() {
	if (loopRunning) {
		return;
	}
	loopRunning = true;

	while (true) {
		try {
			await new Promise((r) => setTimeout(r, 5000));
			const requests = await credentialRequestHelper.getCredentialRequests();
			if (!requests) {
				continue;
			}
			await Promise.all(
				requests
					.filter((req) => req.status === 'pending' && req.scope.split(' ').includes('por:sd_jwt_vc'))
					.map(async (r) => {
						const supportedConf = findSupportedCredentialByScope('por:sd_jwt_vc');
						if (!supportedConf || !('vct' in supportedConf)) {
							return null;
						}
						const acc = await getAccountEntryById(r.sub);
						if (!acc) {
							return null;
						}
						await credentialRequestHelper.fulfilCredentialRequest(r.transaction_id, {
							sub: r.sub,
							vct: supportedConf.vct,
							...acc.por,
						});
					}),
			);
		} catch (err) {
			console.error(err);
		}

		await new Promise((resolve) => setImmediate(resolve));
	}
}

runLoop();

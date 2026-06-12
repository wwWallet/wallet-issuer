import fs from 'node:fs/promises';
import path from 'path';
import { ClaimsProvider, ClaimsProviderResult, ClaimsResolutionContext } from '../ClaimsProvider';
import { convertPidSdJwtVcToMdoc } from '../../lib/issuer/convertPidSdJwtVcToMdoc';
import { supportedCredentialConfigurations } from '../../../config/supportedCredentialConfigurations';
import { CredentialRequestHelper } from '../../lib/issuer/CredentialRequestHelper';

type AccountEntry = {
	id: string;
	[key: string]: unknown;
};

const findSupportedCredentialByScope = (scope: string) => {
	const result = Object.entries(supportedCredentialConfigurations).filter(([_k, v]) => v.scope === scope)[0];
	if (!result) {
		return null;
	}
	const [_credentialConfigurationId, credentialConfiguration] = result;
	return credentialConfiguration;
};

const resolveSupportedScopeToken = (scope: string): string | undefined => {
	const scopes = scope.split(' ');
	for (let i = 0; i < scopes.length; i++) {
		if (findSupportedCredentialByScope(scopes[i])) {
			return scopes[i];
		}
	}
	return undefined;
};

export class FilesystemClaimsProvider implements ClaimsProvider {
	private loopRunning = false;

	private async getAccountEntryById(id: string): Promise<AccountEntry | null> {
		const data = await fs.readFile(path.join(__dirname, '../../../../dataset/accounts.json'), 'utf-8');
		const parsedData = JSON.parse(data.toString());
		return parsedData.accounts.filter((r: AccountEntry) => r.id === id)[0] ?? null;
	}

	async resolveAccountId(sub: string): Promise<string | null> {
		const account = await this.getAccountEntryById(sub);
		return account?.id ?? null;
	}

	async resolveClaims(accountId: string, scope: string, _context?: ClaimsResolutionContext): Promise<ClaimsProviderResult> {
		const account = await this.getAccountEntryById(accountId);
		if (!account) {
			return { kind: 'denied', reason: 'Account not found' };
		}

		const supportedScope = resolveSupportedScopeToken(scope);
		if (!supportedScope) {
			return { kind: 'denied', reason: 'Not supported scope' };
		}

		let releasedClaims = {};
		if (supportedScope === 'por:sd_jwt_vc') {
			return { kind: 'pending' };
		}

		const supportedConf = findSupportedCredentialByScope(supportedScope);
		if (!supportedConf) {
			return { kind: 'denied', reason: 'Not supported scope' };
		}
		if (supportedConf && 'vct' in supportedConf) {
			releasedClaims = { ...releasedClaims, vct: supportedConf.vct };
		}

		const claimsBucket = supportedScope.split(':')[0];
		const accountClaims = account[claimsBucket];
		if (!accountClaims || typeof accountClaims !== 'object') {
			return { kind: 'denied', reason: `No claims found for scope '${supportedScope}'` };
		}

		if (supportedScope === 'pid:mso_mdoc') {
			releasedClaims = { ...convertPidSdJwtVcToMdoc(accountClaims as Record<string, unknown>) };
		} else {
			releasedClaims = { ...releasedClaims, ...accountClaims };
		}

		return { kind: 'ready', claims: releasedClaims };
	}

	startBackgroundJobs(credentialRequestHelper: CredentialRequestHelper): void {
		if (this.loopRunning) {
			return;
		}
		this.loopRunning = true;
		void this.runLoop(credentialRequestHelper);
	}

	private async runLoop(credentialRequestHelper: CredentialRequestHelper) {
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
							const acc = await this.getAccountEntryById(r.sub);
							if (!acc) {
								return null;
							}
							const porClaims = acc.por;
							if (!porClaims || typeof porClaims !== 'object') {
								return null;
							}
							await credentialRequestHelper.fulfilCredentialRequest(r.transaction_id, {
								sub: r.sub,
								vct: supportedConf.vct,
								...porClaims,
							});
							return null;
						}),
				);
			} catch (error) {
				console.error(error);
			}

			await new Promise((resolve) => setImmediate(resolve));
		}
	}
}

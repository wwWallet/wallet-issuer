import fs from 'node:fs/promises';
import path from 'path';
import { ClaimsProvider, ClaimsProviderResult } from '../ClaimsProvider';
import { convertPidSdJwtVcToMdoc } from '../../lib/issuer/convertPidSdJwtVcToMdoc';
import { supportedCredentialConfigurations } from '../../../config/supportedCredentialConfigurations';
import { CredentialRequestHelper } from '../../lib/issuer/CredentialRequestHelper';

type AccountEntry = {
	id: string;
	pid: Record<string, unknown>;
	diploma: Record<string, unknown>;
	ehic: Record<string, unknown>;
	por: Record<string, unknown>;
	esc: Record<string, unknown>;
};

const findSupportedCredentialByScope = (scope: string) => {
	const result = Object.entries(supportedCredentialConfigurations).filter(([_k, v]) => v.scope === scope)[0];
	if (!result) {
		return null;
	}
	const [_credentialConfigurationId, credentialConfiguration] = result;
	return credentialConfiguration;
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

	async resolveClaims(accountId: string, scope: string): Promise<ClaimsProviderResult> {
		const account = await this.getAccountEntryById(accountId);
		if (!account) {
			return { kind: 'denied', reason: 'Account not found' };
		}

		let releasedClaims = {};
		if (scope.split(' ').includes('por:sd_jwt_vc')) {
			return { kind: 'pending' };
		}
		else if (scope.split(' ').includes('pid:sd_jwt_dc')) {
			const supportedConf = findSupportedCredentialByScope('pid:sd_jwt_dc');
			if (supportedConf && 'vct' in supportedConf) {
				releasedClaims = { ...releasedClaims, vct: supportedConf.vct };
			}
			releasedClaims = { ...releasedClaims, ...account.pid };
		}
		else if (scope.split(' ').includes('pid:mso_mdoc')) {
			releasedClaims = { ...convertPidSdJwtVcToMdoc(account.pid) };
		}
		else if (scope.split(' ').includes('ehic')) {
			const supportedConf = findSupportedCredentialByScope('ehic');
			if (supportedConf && 'vct' in supportedConf) {
				releasedClaims = { ...releasedClaims, vct: supportedConf.vct };
			}
			releasedClaims = { ...releasedClaims, ...account.ehic };
		}
		else if (scope.split(' ').includes('diploma')) {
			const supportedConf = findSupportedCredentialByScope('diploma');
			if (supportedConf && 'vct' in supportedConf) {
				releasedClaims = { ...releasedClaims, vct: supportedConf.vct };
			}
			releasedClaims = { ...releasedClaims, ...account.diploma };
		}
		else if (scope.split(' ').includes('esc')) {
			const supportedConf = findSupportedCredentialByScope('esc');
			if (supportedConf && 'vct' in supportedConf) {
				releasedClaims = { ...releasedClaims, vct: supportedConf.vct };
			}
			releasedClaims = { ...releasedClaims, ...account.esc };
		}
		else {
			return { kind: 'denied', reason: 'Not supported scope' };
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
							await credentialRequestHelper.fulfilCredentialRequest(r.transaction_id, {
								sub: r.sub,
								vct: supportedConf.vct,
								...acc.por,
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

import { ClaimsProvider, ClaimsProviderResult, ClaimsResolutionContext } from '../ClaimsProvider';
import { ClaimsSourceConfiguration } from '../../../config/claimsSourceConfigurations';
import { supportedCredentialConfigurations } from '../../../config/supportedCredentialConfigurations';
import { CredentialRequestHelper } from '../../lib/issuer/CredentialRequestHelper';
import { FilesystemClaimsProvider } from './FilesystemClaimsProvider';
import { RemoteClaimsProvider } from './RemoteClaimsProvider';

type ClaimsSourceConfigurationByScope = Record<string, ClaimsSourceConfiguration>;

export class ConfigurationClaimsProvider implements ClaimsProvider {
	private readonly providersByScope = new Map<string, ClaimsProvider>();
	private readonly hasRemoteProvider: boolean;

	constructor(
		claimsSources: ClaimsSourceConfigurationByScope,
		private readonly filesystemProvider: ClaimsProvider = new FilesystemClaimsProvider(),
	) {
		let hasRemoteProvider = false;
		for (const credentialConfiguration of Object.values(supportedCredentialConfigurations)) {
			const scope = credentialConfiguration.scope;
			if (typeof scope !== 'string' || this.providersByScope.has(scope)) {
				continue;
			}

			const source = claimsSources[scope] ?? { type: 'filesystem' };
			if (source.type === 'remote') {
				this.validateRemoteUrl(scope, source.url);
				hasRemoteProvider = true;
			}
			const provider = source.type === 'remote'
				? new RemoteClaimsProvider(source.url, {
					supportedScopes: [scope],
					apiKey: source.apiKey,
					apiKeyHeaderName: source.apiKeyHeaderName,
					fetchTimeoutMs: source.fetchTimeoutMs,
				})
				: this.filesystemProvider;

			this.providersByScope.set(scope, provider);
		}
		this.hasRemoteProvider = hasRemoteProvider;
	}

	private validateRemoteUrl(scope: string, urlValue: string): void {
		try {
			const url = new URL(urlValue);
			if (url.protocol !== 'http:' && url.protocol !== 'https:') {
				throw new Error('unsupported protocol');
			}
		} catch {
			throw new Error(`Invalid remote claims URL for scope '${scope}'`);
		}
	}

	async resolveAccountId(sub: string): Promise<string | null> {
		return this.hasRemoteProvider ? sub : this.filesystemProvider.resolveAccountId(sub);
	}

	async resolveClaims(accountId: string, scope: string, context?: ClaimsResolutionContext): Promise<ClaimsProviderResult> {
		for (const scopeToken of scope.split(' ')) {
			const provider = this.providersByScope.get(scopeToken);
			if (provider) {
				return provider.resolveClaims(accountId, scopeToken, context);
			}
		}
		return { kind: 'denied', reason: 'Not supported scope' };
	}

	startBackgroundJobs(credentialRequestHelper: CredentialRequestHelper): void {
		if ([...this.providersByScope.values()].includes(this.filesystemProvider)) {
			this.filesystemProvider.startBackgroundJobs?.(credentialRequestHelper);
		}
	}
}

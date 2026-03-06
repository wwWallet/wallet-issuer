import { ClaimsProvider, ClaimsProviderResult } from '../ClaimsProvider';
import { supportedCredentialConfigurations } from '../../../config/supportedCredentialConfigurations';

type ClaimsPayload = Record<string, unknown>;
const DEFAULT_SUPPORTED_SCOPES = Object.values(supportedCredentialConfigurations)
	.map((configuration) => configuration.scope)
	.filter((scope): scope is string => typeof scope === 'string');

export class RemoteClaimsProvider implements ClaimsProvider {
	private readonly supportedScopesSet: ReadonlySet<string>;

	constructor(
		private readonly claimsFetcherUrl: string,
		supportedScopes: readonly string[] = DEFAULT_SUPPORTED_SCOPES,
	) {
		this.supportedScopesSet = new Set(supportedScopes);
	}

	async resolveAccountId(sub: string): Promise<string | null> {
		return sub;
	}

	async resolveClaims(accountId: string, scope: string): Promise<ClaimsProviderResult> {
		const supportedScope = this.resolveSupportedScope(scope);
		if (!supportedScope) {
			return { kind: 'denied', reason: 'Not supported scope' };
		}

		const fetchedClaims = await this.getClaimsByUserId(accountId, supportedScope);
		if (!fetchedClaims) {
			return { kind: 'denied', reason: 'Could not fetch claims' };
		}

		const vct = this.resolveVct(supportedScope);
		return {
			kind: 'ready',
			claims: {
				...(vct ? { vct } : {}),
				...fetchedClaims,
			},
		};
	}

	private resolveSupportedScope(scope: string): string | undefined {
		const scopeTokens = scope.split(' ');
		for (let i = 0; i < scopeTokens.length; i++) {
			if (this.supportedScopesSet.has(scopeTokens[i])) {
				return scopeTokens[i];
			}
		}
		return undefined;
	}

	private resolveVct(scope: string): string | undefined {
		const configurationEntry = Object.entries(supportedCredentialConfigurations).find(([, configuration]) => configuration.scope === scope);
		const configuration = configurationEntry?.[1];
		if (!configuration || !('vct' in configuration)) {
			return undefined;
		}
		return configuration.vct;
	}

	private async getClaimsByUserId(userId: string, scope: string): Promise<ClaimsPayload | null> {
		try {
			const url = new URL(this.claimsFetcherUrl);
			url.searchParams.append('userId', userId);
			url.searchParams.append('scope', scope);

			const response = await fetch(url);
			if (!response.ok) {
				return null;
			}

			const body = await response.json() as unknown;
			if (!body || typeof body !== 'object' || Array.isArray(body)) {
				return null;
			}

			return body as ClaimsPayload;
		} catch {
			return null;
		}
	}
}

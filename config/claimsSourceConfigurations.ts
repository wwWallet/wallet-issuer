import { supportedCredentialConfigurations } from './supportedCredentialConfigurations';
import { logger } from '../src/logger';

export type ClaimsSourceDefinition =
	| { type: 'filesystem' }
	| {
		type: 'remote';
		urlEnvironmentVariable: string;
		apiKeyEnvironmentVariable?: string;
		apiKeyHeaderName?: string;
		fetchTimeoutMs?: number;
	};

export type ClaimsSourceConfiguration =
	| { type: 'filesystem' }
	| {
		type: 'remote';
		url: string;
		apiKey?: string;
		apiKeyHeaderName?: string;
		fetchTimeoutMs?: number;
	};

type LocalClaimsSourceConfigurations = {
	claimsSourceConfigurations?: Record<string, ClaimsSourceDefinition>;
};

const loadLocalClaimsSourceConfigurations = (): LocalClaimsSourceConfigurations => {
	try {
		return require('./claimsSourceConfigurations.local') as LocalClaimsSourceConfigurations;
	} catch (error) {
		if (
			typeof error === 'object' &&
			error !== null &&
			'code' in error &&
			error.code === 'MODULE_NOT_FOUND' &&
			'message' in error &&
			typeof error.message === 'string' &&
			error.message.includes('claimsSourceConfigurations.local')
		) {
			return {};
		}
		throw error;
	}
};

const environmentValue = (name: string): string => process.env[name]?.trim() ?? '';

const localClaimsSources = loadLocalClaimsSourceConfigurations().claimsSourceConfigurations;

/** When the local map exists it is authoritative: omitted credentials use filesystem. */
const claimsSourceEntries: Array<[string, ClaimsSourceConfiguration]> = [];
if (localClaimsSources) {
	const supportedScopes = new Set(Object.values(supportedCredentialConfigurations)
		.map((credentialConfiguration) => credentialConfiguration.scope)
		.filter((scope): scope is string => typeof scope === 'string'));
	for (const scope of Object.keys(localClaimsSources)) {
		if (!supportedScopes.has(scope)) {
			logger.warn('Ignoring claims source configuration for unknown scope', { scope });
		}
	}

	for (const credentialConfiguration of Object.values(supportedCredentialConfigurations)) {
		const scope = credentialConfiguration.scope;
		if (typeof scope !== 'string') {
			continue;
		}
		const source = localClaimsSources[scope] ?? { type: 'filesystem' };
		if (source.type === 'filesystem') {
			claimsSourceEntries.push([scope, source]);
			continue;
		}

		claimsSourceEntries.push([scope, {
			type: 'remote',
			url: environmentValue(source.urlEnvironmentVariable),
			apiKey: source.apiKeyEnvironmentVariable
				? environmentValue(source.apiKeyEnvironmentVariable) || undefined
				: undefined,
			apiKeyHeaderName: source.apiKeyHeaderName,
			fetchTimeoutMs: source.fetchTimeoutMs,
		}]);
	}
}

export const claimsSourceConfigurations: Record<string, ClaimsSourceConfiguration> = Object.fromEntries(claimsSourceEntries);

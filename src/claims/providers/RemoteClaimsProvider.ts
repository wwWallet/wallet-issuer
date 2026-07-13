import { ClaimsProvider, ClaimsProviderResult, ClaimsResolutionContext } from '../ClaimsProvider';
import { supportedCredentialConfigurations } from '../../../config/supportedCredentialConfigurations';
import { logger } from '../../logger';

type ClaimsPayload = Record<string, unknown>;
type ClaimsFetchResult =
	| { kind: 'success'; claims: ClaimsPayload }
	| { kind: 'failure'; reason: string };

const DEFAULT_FETCH_TIMEOUT_MS = 5000;
const DEFAULT_SUPPORTED_SCOPES = Object.values(supportedCredentialConfigurations)
	.map((configuration) => configuration.scope)
	.filter((scope): scope is string => typeof scope === 'string');

export class RemoteClaimsProvider implements ClaimsProvider {
	private readonly supportedScopesSet: ReadonlySet<string>;
	private readonly apiKey: string;
	private readonly apiKeyHeaderName: string;
	private readonly fetchTimeoutMs: number;

	constructor(
		private readonly claimsFetcherUrl: string,
		options: {
			supportedScopes?: readonly string[];
			apiKey?: string;
			apiKeyHeaderName?: string;
			fetchTimeoutMs?: number;
		} = {},
	) {
		const supportedScopes = options.supportedScopes ?? DEFAULT_SUPPORTED_SCOPES;
		this.supportedScopesSet = new Set(supportedScopes);
		this.apiKey = (options.apiKey ?? '').trim();
		this.apiKeyHeaderName = (options.apiKeyHeaderName ?? 'x-api-key').trim() || 'x-api-key';
		this.fetchTimeoutMs = options.fetchTimeoutMs && options.fetchTimeoutMs > 0
			? options.fetchTimeoutMs
			: DEFAULT_FETCH_TIMEOUT_MS;
	}

	async resolveAccountId(sub: string): Promise<string | null> {
		return sub;
	}

	async resolveClaims(accountId: string, scope: string, context?: ClaimsResolutionContext): Promise<ClaimsProviderResult> {
		const supportedScope = this.resolveSupportedScope(scope);
		if (!supportedScope) {
			return { kind: 'denied', reason: 'Not supported scope' };
		}

		const fetchedClaimsResult = await this.getClaimsByUserId(accountId, supportedScope, context?.claimsContext);
		if (fetchedClaimsResult.kind === 'failure') {
			return { kind: 'denied', reason: `Could not fetch claims: ${fetchedClaimsResult.reason}` };
		}

		const vct = this.resolveVct(supportedScope);
		return {
			kind: 'ready',
			claims: {
				...(vct ? { vct } : {}),
				...fetchedClaimsResult.claims,
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

	private async getClaimsByUserId(userId: string, scope: string, claimsContext?: string): Promise<ClaimsFetchResult> {
		const controller = new AbortController();
		const timeout = setTimeout(() => controller.abort(), this.fetchTimeoutMs);

		try {
			const url = new URL(this.claimsFetcherUrl);
			console.log('Fetching claims from remote service', { url: url.toString(), scope });
			const headers = new Headers();
			headers.set('content-type', 'application/json');
			if (this.apiKey) {
				headers.set(this.apiKeyHeaderName, this.apiKey);
			}
			console.log('Request headers', { headers: Object.fromEntries(headers.entries()) });
			const requestData = {
				sub: userId,
				...(claimsContext ? { claims_context: claimsContext } : {}),
			};
			console.log('Request body', requestData);
			const response = await fetch(url, {
				method: 'POST',
				headers,
				body: JSON.stringify({
					data: requestData,
				}),
				signal: controller.signal,
			});
			if (!response.ok) {
				const reason = this.resolveHttpFailureReason(response.status);
				logger.warn('Remote claims fetch failed', { status: response.status, scope, reason });
				return { kind: 'failure', reason };
			}

			const body = await response.json() as unknown;
			console.log('Fetched claims response body', { body });
			if (!this.isRecord(body) || !this.isRecord(body.data)) {
				logger.warn('Remote claims fetch returned invalid payload', { scope });
				return { kind: 'failure', reason: 'invalid_response_payload' };
			}

			return { kind: 'success', claims: body.data as ClaimsPayload };
		} catch (error) {
			if (this.isAbortError(error)) {
				logger.warn('Remote claims fetch timed out', { scope, timeoutMs: this.fetchTimeoutMs });
				return { kind: 'failure', reason: 'request_timeout' };
			}

			logger.error('Remote claims fetch failed', { scope, error });
			return { kind: 'failure', reason: 'request_failed' };
		} finally {
			clearTimeout(timeout);
		}
	}

	private resolveHttpFailureReason(status: number): string {
		if (status === 401 || status === 403) {
			return 'unauthorized';
		}
		if (status === 429) {
			return 'rate_limited';
		}
		if (status === 408 || status === 504) {
			return 'upstream_timeout';
		}
		if (status >= 500) {
			return 'upstream_service_error';
		}
		if (status >= 400) {
			return 'bad_request_to_claims_service';
		}
		return 'unexpected_response_status';
	}

	private isAbortError(error: unknown): boolean {
		return error instanceof Error && error.name === 'AbortError';
	}

	private isRecord(value: unknown): value is Record<string, unknown> {
		return !!value && typeof value === 'object' && !Array.isArray(value);
	}
}

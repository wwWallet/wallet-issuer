import { CredentialRequestHelper } from '../lib/issuer/CredentialRequestHelper';

export type ClaimsProviderResult =
	| { kind: 'ready'; claims: Record<string, unknown> }
	| { kind: 'pending' }
	| { kind: 'denied'; reason: string };

export type ClaimsResolutionContext = {
	claimsContext?: string;
};

export interface ClaimsProvider {
	resolveAccountId(sub: string): Promise<string | null>;
	resolveClaims(accountId: string, scope: string, context?: ClaimsResolutionContext): Promise<ClaimsProviderResult>;
	startBackgroundJobs?(credentialRequestHelper: CredentialRequestHelper): void;
}

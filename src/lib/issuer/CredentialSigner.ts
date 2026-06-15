import { HasherAndAlg, Signer } from '@sd-jwt/types';
import { JWK } from 'jose';
import { CredentialConfigurationSupported } from 'wallet-common';

export interface CredentialSigner {
	/**
	 *
	 * @param payload
	 * @param headers
	 * @param disclosureFrame ex. { claimX: true, claimY: { claimR: false, claimH: true }}
	 */
	signSdJwtVc(payload: any, headers?: any, disclosureFrame?: any): Promise<{ credential: string }>;
	signMsoMdoc(credentialConfiguration: CredentialConfigurationSupported, claims: Record<string, unknown>, holderPublicKeyJwk: JWK): Promise<{ credential: string }>;
	getPublicKeyJwk(): Promise<JWK>;
	signer(): Signer;
	hasherAndAlgorithm: HasherAndAlg;
	saltGenerator: () => string;
}

import { HasherAndAlg, Signer } from '@sd-jwt/types';
import { JWK } from 'jose';

export interface CredentialSigner {
	signSdJwtVc(payload: any, headers?: any): Promise<{ credential: string }>;
	signMsoMdoc(
		doctype: string,
		namespaces: Map<string, Record<string, unknown>>,
		holderPublicKeyJwk: JWK,
	): Promise<{ credential: string }>;
	getPublicKeyJwk(): Promise<JWK>;
	signer(): Signer;
	hasherAndAlgorithm: HasherAndAlg;
	saltGenerator: () => string;
}

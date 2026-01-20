import { OpenidCredentialIssuerMetadata } from 'wallet-common';
import { CredentialIssuerCreateOptions } from './IssuerOpenID4VCI';

export function buildMetadata(url: string, credentialIssuerCreateOptions: CredentialIssuerCreateOptions): OpenidCredentialIssuerMetadata {
	return {
		credential_issuer: url,
		authorization_servers: [credentialIssuerCreateOptions.authorizationServerUrl],
		credential_endpoint: url + '/credential',
		deferred_credential_endpoint: url + '/deferred-credential',
		nonce_endpoint: url + '/nonce',
		credential_configurations_supported: {},
		credential_request_encryption: credentialIssuerCreateOptions.credentialRequestEncryption
			? {
					encryption_required: credentialIssuerCreateOptions.credentialRequestEncryption?.encryptionRequired ?? false,
					enc_values_supported: ['A256GCM'],
					jwks: [
						{
							kid: credentialIssuerCreateOptions.credentialRequestEncryption.keypair.publicKeyJwk.kid as string,
							...credentialIssuerCreateOptions.credentialRequestEncryption.keypair.publicKeyJwk,
						},
					],
				}
			: undefined,
		credential_response_encryption: credentialIssuerCreateOptions.credentialResponseEncryption
			? {
					encryption_required: credentialIssuerCreateOptions.credentialResponseEncryption.encryptionRequired ?? false,
					enc_values_supported: ['A256GCM'],
					alg_values_supported: ['ECDH-ES'],
				}
			: undefined,
		display: credentialIssuerCreateOptions.display ? credentialIssuerCreateOptions.display : [{ locale: 'en-US', name: 'wwWallet Issuer' }],
	} as OpenidCredentialIssuerMetadata;
}

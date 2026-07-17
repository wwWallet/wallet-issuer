import { config } from '../../config';
import { createIssuerOpenID4VCI, ProofTypesSupported } from '../lib/issuer';
import { LocalTrustedCertificatesManager } from './LocalTrustedCertificatesManager';
import fs from 'fs';
import path from 'path';
import { signer } from '../signer';
import { disclosureFrameMap, supportedCredentialConfigurations } from '../../config/supportedCredentialConfigurations';
import { pemToBase64 } from '../util/pemToBase64';
import { JWK } from 'jose';
import { vctDocumentProvider } from '../../config/vctDocumentProvider';
import { createCredentialRequestHelper, CredentialRequestWithClaims } from '../lib/issuer/CredentialRequestHelper';
import { createFindAccount } from '../claims/createFindAccount';
import { ClaimsProvider } from '../claims/ClaimsProvider';
import { FilesystemClaimsProvider } from '../claims/providers/FilesystemClaimsProvider';
import { RemoteClaimsProvider } from '../claims/providers/RemoteClaimsProvider';
import { DataStore } from '../store/DataStore';
import { dataStoreClient } from '../store/dataStoreClient';

const localTrustedCertsManager = LocalTrustedCertificatesManager();

const secret = fs.readFileSync(path.join(__dirname, '../../../keys/secret.hs512.b64'), 'utf-8').toString().trim();

const privateKeyJwk = JSON.parse(fs.readFileSync(path.join(__dirname, '../../../keys/private.enc.ecdh.jwk'), 'utf-8').toString().trim()) as JWK;

const publicKeyJwk = JSON.parse(fs.readFileSync(path.join(__dirname, '../../../keys/public.enc.ecdh.jwk'), 'utf-8').toString().trim()) as JWK;

const credentialRequestStore = new DataStore<CredentialRequestWithClaims>(dataStoreClient, "credentialRequest");
const credentialRequestIndexStore = new DataStore<string>(dataStoreClient, "credentialRequestIndex");

export const credentialRequestHelper = createCredentialRequestHelper(credentialRequestStore, credentialRequestIndexStore);

const claimsProvider: ClaimsProvider = config.vcClaimsFetcherEnabled && config.vcClaimsFetcherUrl
	? new RemoteClaimsProvider(config.vcClaimsFetcherUrl, { apiKey: config.vcClaimsFetcherApiKey })
	: new FilesystemClaimsProvider();

claimsProvider.startBackgroundJobs?.(credentialRequestHelper);
const configuredFindAccount = createFindAccount(claimsProvider);

export const issuer = createIssuerOpenID4VCI(config.issuerIdentifier, {
	clockTolerance: config.clockTolerance,
	deferredCredentialResponseInterval: config.deferredCredentialResponseInterval,
	findAccount: configuredFindAccount,
	credentialRequestHelper,
	proofTypesSupported: [ProofTypesSupported.JWT, ProofTypesSupported.ATTESTATION],
	requireKeyBindingInCredentialConfigurationIds: [],
	getAllTrustedPemCertificates: localTrustedCertsManager.getAllPemCertificates,
	secret: secret,
	authorizationServerUrl: config.authorizationServerUrl,
	credentialSigner: signer,
	x5c: [pemToBase64(fs.readFileSync(path.join(__dirname, '../../../keys/pem.crt'), 'utf-8'))],
	introspectionEndpointBasicAuthString: config.introspectionEndpointBasicAuthString,
	credentialRequestEncryption: {
		encryptionRequired: false,
		keypair: {
			alg: config.jweEncryptionAlg,
			publicKeyJwk: publicKeyJwk,
			privateKeyJwk: privateKeyJwk,
		},
	},
	display: config.display,
	vctDocumentProvider: vctDocumentProvider,
});

Object.entries(supportedCredentialConfigurations).map(([credentialConfigurationId, conf]) => issuer.registerSupportedCredentialConfiguration(credentialConfigurationId, conf, disclosureFrameMap[credentialConfigurationId]));

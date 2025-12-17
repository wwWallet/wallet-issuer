import { config } from "../../config";
import { findAccount } from "../../config/accountFinder";
import { createIssuerOpenID4VCI, ProofTypesSupported } from "../lib/issuer";
import { LocalTrustedCertificatesManager } from "./LocalTrustedCertificatesManager";
import fs from 'fs';
import path from 'path';
import { signer } from "../signer";
import { supportedCredentialConfigurations } from "../../config/supportedCredentialConfigurations";
import { pemToBase64 } from "../util/pemToBase64";
import * as fsPromises from 'fs/promises';
import { JWK } from "jose";

const { writeFile } = fsPromises;

const localTrustedCertsManager = LocalTrustedCertificatesManager();

const secret = fs.readFileSync(path.join(__dirname, "../../../keys/secret.hs512.b64"), 'utf-8')
	.toString()
	.trim();

const privateKeyJwk = JSON.parse(fs.readFileSync(path.join(__dirname, "../../../keys/private.enc.ecdh.jwk"), 'utf-8')
	.toString()
	.trim()) as JWK;

const publicKeyJwk = JSON.parse(fs.readFileSync(path.join(__dirname, "../../../keys/public.enc.ecdh.jwk"), 'utf-8')
	.toString()
	.trim()) as JWK;

export const issuer = createIssuerOpenID4VCI(config.url + '/openid', {
	clockTolerance: config.clockTolerance,
	findAccount: findAccount,
	proofTypesSupported: [ProofTypesSupported.JWT, ProofTypesSupported.ATTESTATION],
	requireKeyBindingInCredentialConfigurationIds: [],
	getAllTrustedPemCertificates: localTrustedCertsManager.getAllPemCertificates,
	secret: secret,
	authorizationServerUrl: config.authorizationServerUrl,
	credentialSigner: signer,
	x5c: [
		pemToBase64(fs.readFileSync(path.join(__dirname, "../../../keys/pem.crt"), 'utf-8')),
	],
	introspectionEndpointBearerAuthToken: config.introspectionEndpointBearerAuthToken,
	credentialRequestEncryption: {
		encryptionRequired: false,
		keypair: {
			alg: config.jweEncryptionAlg,
			publicKeyJwk: publicKeyJwk,
			privateKeyJwk: privateKeyJwk,
		},
	},
	display: config.display,
});

Object.entries(supportedCredentialConfigurations).map(([credentialConfigurationId, conf]) =>
	issuer.registerSupportedCredentialConfiguration(credentialConfigurationId, conf)
);


issuer.getMetadata().then((async (metadata) => {
	await writeFile(path.join(__dirname, "../../../public/.well-known/openid-credential-issuer"), JSON.stringify(metadata));
}))

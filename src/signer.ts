import { config } from '../config';
import { CredentialSigner } from './lib/issuer/CredentialSigner';
import fs from 'fs';
import path from 'path';
import { SDJwtInstance } from '@sd-jwt/core';
import { digest as hasher } from '@sd-jwt/crypto-nodejs';
import { createPrivateKey, sign, randomBytes, KeyObject, webcrypto, randomUUID } from 'crypto';
import { importPrivateKeyPem } from './util/importPrivateKeyPem';
import { calculateJwkThumbprint, exportJWK, importX509 } from 'jose';
import { CoseKey, DeviceKey, Issuer, SignatureAlgorithm, type MdocContext } from '@owf/mdoc';
import { logger } from './logger';
import { calculateObjectSRI } from 'wallet-common';
import { vctDocumentProvider } from '../config/vctDocumentProvider';

const issuerPrivateKeyPem = fs.readFileSync(path.join(__dirname, '../../keys/pem.key'), 'utf-8').toString();
const issuerCertPem = fs.readFileSync(path.join(__dirname, '../../keys/pem.crt'), 'utf-8').toString() as string;

const parsePemCertificateChain = (pem: string) => {
	const matches = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
	if (!matches || matches.length === 0) {
		throw new Error('No certificate found in issuer certificate PEM');
	}

	return matches.map((certPemBlock) =>
		certPemBlock
			.replace(/-----BEGIN CERTIFICATE-----/g, '')
			.replace(/-----END CERTIFICATE-----/g, '')
			.replace(/\r?\n|\r/g, '')
	);
};

const issuerX5C = parsePemCertificateChain(issuerCertPem);
const issuerCertDerChain = issuerX5C.map((certB64) => new Uint8Array(Buffer.from(certB64, 'base64')));

importPrivateKeyPem(issuerPrivateKeyPem, 'ES256'); // attempt to import the key
importX509(issuerCertPem, 'ES256'); // attempt to import the public key

const issuerJwkKid = '8636af04-5796-4f46-a73e-d690d7d4e7f3';

const key = async function () {
	const key = await importPrivateKeyPem(issuerPrivateKeyPem, 'ES256');
	if (!key) {
		throw new Error('Could not import private key');
	}
	return key as any;
};

const mdocContext = {
	crypto: {
		digest: async ({ digestAlgorithm, bytes }) => {
			const digest = await webcrypto.subtle.digest(digestAlgorithm, bytes as Uint8Array<ArrayBuffer>);
			return new Uint8Array(digest);
		},
		random: (length: number) => webcrypto.getRandomValues(new Uint8Array(length)),
		calculateEphemeralMacKey: async () => {
			throw new Error('calculateEphemeralMacKey is not used in issuer flow');
		},
	},
	cose: {
		mac0: {
			sign: async () => {
				throw new Error('mac0.sign is not used in issuer flow');
			},
			verify: async () => {
				throw new Error('mac0.verify is not used in issuer flow');
			},
		},
		sign1: {
			sign: async ({ key, toBeSigned }) => {
				const privateKey = createPrivateKey({ format: 'jwk', key: key.jwk as Record<string, unknown> });
				return new Uint8Array(
					sign(null, toBeSigned, {
						dsaEncoding: 'ieee-p1363',
						key: privateKey,
					})
				);
			},
			verify: async () => {
				throw new Error('cose.sign1.verify is not used in issuer flow');
			},
		},
	},
} satisfies Pick<MdocContext, 'crypto' | 'cose'>;

export const signer: CredentialSigner = {
	signMsoMdoc: async function (doctype, namespaces, holderPublicKeyJwk) {
		const key = await importPrivateKeyPem(issuerPrivateKeyPem, 'ES256');
		if (!key) {
			throw new Error('Could not import private key');
		}

		const issuer = new Issuer(doctype, mdocContext);

		for (const [ns, nsData] of namespaces) {
			issuer.addIssuerNamespace(ns, { ...nsData });
		}

		const issuerPrivateKeyJwk = await exportJWK(key);
		const signed = new Date();
		const validFromDate = new Date(signed.getTime() + 1000);
		const expirationDate = new Date();

		expirationDate.setFullYear(expirationDate.getFullYear() + 1);

		const issuerSigned = await issuer.sign({
			signingKey: CoseKey.fromJwk({
				...issuerPrivateKeyJwk,
				kid: issuerJwkKid,
			} as Record<string, unknown>),
			certificates: issuerCertDerChain,
			algorithm: SignatureAlgorithm.ES256,
			digestAlgorithm: 'SHA-256',
			deviceKeyInfo: {
				deviceKey: DeviceKey.fromJwk(holderPublicKeyJwk as Record<string, unknown>),
			},
			validityInfo: {
				signed,
				validFrom: validFromDate,
				validUntil: expirationDate,
			},
		});

		const credential = issuerSigned.encodedForOid4Vci;
		return { credential };
	},
	signSdJwtVc: async function (payload, headers, disclosureFrame) {
		if (!payload?.vct) {
			throw new Error('payload.vct is required in SD JWT VCs');
		}
		const doc = await vctDocumentProvider.getVctMetadataDocument(payload.vct);
		if (doc?.ok) {
			const typeMetadata = doc.value;
			const vctIntegrity = await calculateObjectSRI(crypto.subtle, typeMetadata);
			if (vctIntegrity) {
				payload['vct#integrity'] = vctIntegrity;
			}
			else {
				logger.warn(`Unable to calculate VCT integrity for vct ${payload.vct}`);
			}
		}
		else {
			logger.warn(`Unable to find VCT Metadata for vct ${payload.vct}`);
		}

		const issuanceDate = new Date();
		const expirationDate = new Date();
		expirationDate.setFullYear(expirationDate.getFullYear() + 1);

		headers.x5c = issuerX5C;
		headers.typ = 'dc+sd-jwt';

		if (!disclosureFrame) {
			throw new Error('Could not generate signature');
		}

		payload.iat = Math.floor(issuanceDate.getTime() / 1000);
		payload.nbf = Math.floor(issuanceDate.getTime() / 1000);
		payload.exp = Math.floor(expirationDate.getTime() / 1000);
		if (!payload?.cnf?.jwk) {
			logger.error('payload.cnf.jwk is required in signSdJwtVc function call');
			throw new Error('payload.cnf.jwk is required in signSdJwtVc function call');
		}

		if (config.useAlternativeIdentifier) {
			payload.also_known_as = randomUUID();
			payload.sub = undefined;
		} else {
			payload.sub = await calculateJwkThumbprint(payload.cnf.jwk);
		}
		payload.iss = config.issuerIdentifier;

		// Mark credential as "short-lived", meaning that no status list is needed
		// If not "short-lived", the attribute should not exist at all in the payload.
		if (config.issueShortTermCredentials) {
			payload.shortLived = null;
		}

		if (config.issueOneTimeCredentials) {
			payload.oneTime = null;
		}

		const sdjwt = new SDJwtInstance({
			signer: this.signer(),
			hashAlg: 'sha-256',
			hasher: this.hasherAndAlgorithm.hasher,
			signAlg: 'ES256',
			saltGenerator: this.saltGenerator,
		});

		// Helper function to convert df to work with newer lib
		function disclosureFrameConvert(obj: any) {
			const result: any = {};
			const sd = [];

			for (const [key, value] of Object.entries(obj)) {
				if (value === true) {
					sd.push(key);
				} else if (typeof value === 'object' && value !== null) {
					result[key] = disclosureFrameConvert(value);
				}
			}

			if (sd.length > 0) {
				result['_sd'] = sd;
			}

			return result;
		}

		const credential = await sdjwt.issue(payload, disclosureFrameConvert(disclosureFrame), { header: headers });
		return { credential };
	},
	getPublicKeyJwk: async function () {
		const publicKey = await importX509(issuerCertPem, 'ES256');
		if (!publicKey) {
			throw new Error('Could not import issuer publicKey');
		}
		const jwk = await exportJWK(publicKey);
		return { kid: issuerJwkKid, ...jwk, alg: 'ES256' };
	},
	signer: function () {
		return async (input: string) => {
			const result = sign(null, new Uint8Array(Buffer.from(input)), {
				dsaEncoding: 'ieee-p1363',
				key: (await key()) as KeyObject,
			});
			return result.toString('base64url');
		};
	},
	hasherAndAlgorithm: {
		hasher,
		alg: 'sha-256',
	},
	saltGenerator: () => {
		const buffer = randomBytes(16);
		return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
	},
};

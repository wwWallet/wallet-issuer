import { config } from '../config';
import { CredentialSigner } from './lib/issuer/CredentialSigner';
import fs from 'fs';
import path from 'path';
import { SDJwtInstance } from '@sd-jwt/core';
import { digest as hasher } from '@sd-jwt/crypto-nodejs';
import { sign, randomBytes, KeyObject } from 'crypto';
import { importPrivateKeyPem } from './util/importPrivateKeyPem';
import { calculateJwkThumbprint, exportJWK, importX509 } from 'jose';
import { CoseKey, DeviceKey, Issuer, SignatureAlgorithm, type MdocContext } from '@owf/mdoc';
import { pemToBase64 } from './util/pemToBase64';
import { logger } from './logger';
import { p256 } from '@noble/curves/nist.js';

const issuerPrivateKeyPem = fs.readFileSync(path.join(__dirname, '../../keys/pem.key'), 'utf-8').toString();
const issuerCertPem = fs.readFileSync(path.join(__dirname, '../../keys/pem.crt'), 'utf-8').toString() as string;

const issuerX5C = [pemToBase64(issuerCertPem)];
const issuerCertDer = new Uint8Array(Buffer.from(issuerX5C[0], 'base64'));

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
			const digest = await crypto.subtle.digest(digestAlgorithm, bytes as Uint8Array<ArrayBuffer>);
			return new Uint8Array(digest);
		},
		random: (length: number) => crypto.getRandomValues(new Uint8Array(length)),
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
			sign: async ({ key, toBeSigned }) => p256.sign(toBeSigned, key.privateKey, { format: 'compact' }),
			verify: async ({ sign1, key }) => p256.verify(sign1.signature, sign1.toBeSigned, key.publicKey, { lowS: false }),
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
		certificates: [issuerCertDer],
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
		const issuanceDate = new Date();
		const expirationDate = new Date();
		expirationDate.setFullYear(expirationDate.getFullYear() + 1);

		headers.x5c = issuerX5C;
		headers.typ = 'dc+sd-jwt';

		if (!disclosureFrame) {
			throw new Error('Could not generate signature');
		}

		payload.iat = Math.floor(issuanceDate.getTime() / 1000);
		payload.exp = Math.floor(expirationDate.getTime() / 1000);
		if (!payload?.cnf?.jwk) {
			logger.error('payload.cnf.jwk is required in signSdJwtVc function call');
			throw new Error('payload.cnf.jwk is required in signSdJwtVc function call');
		}
		payload.sub = await calculateJwkThumbprint(payload.cnf.jwk);
		payload.iss = config.url + '/openid';

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

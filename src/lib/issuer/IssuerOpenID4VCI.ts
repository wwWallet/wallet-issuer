import { JWK } from "jose";
import { ProofTypeSupported } from "./types/ProofTypeSupported";
import { CredentialSigner } from "./CredentialSigner";
import { CredentialOfferCreateSuccess, IssueCredentialRequestOptions, IssueCredentialResponse, PlainIssueCredentialResponse } from "./IssuerOpenID4VCITypes";
import { GenericStore } from "../core/Store";
import { State } from "./State";
import { MemoryStore } from "../core/MemoryStore";
import { FindAccount } from "./Account/FindAccount";
import { convertSdjwtvcToOpenid4vciClaims, CredentialConfigurationSupported, CredentialOffer, CredentialOfferSchema, OpenidCredentialIssuerMetadata, OpenidCredentialIssuerMetadataSchema } from "wallet-common";
import { CredentialRequestErrors } from "./CredentialRequest/CredentialRequestError";
import { handleEncryptedCredentialRequest } from "./CredentialRequest/handleEncryptedCredentialRequest";
import { createMemorySecretManager } from "./MemorySecretManager";
import { handleCredentialIdentifierCredentialRequest } from "./CredentialRequest/handleCredentialIdentifierCredentialRequest";
import { toBase64Url } from "wallet-common/dist/utils/util";
import { validateAccessToken } from "./AccessToken/validateAccessToken";
import { verifyProofsWrapper } from "./CredentialRequest/Proof/verifyProof";
import { signCredentials } from "./signCredentials";
import { sendCredentialResponse } from "./CredentialRequest/sendCredentialResponse";
import { generateRandomIdentifier } from "../core/generateRandomIdentifier";
import { sendError } from "./sendError";
import { buildMetadata } from "./buildMetadata";
import { VctDocumentProvider } from "../core/VctDocumentProvider";
import { VerifiableCredentialFormat } from "wallet-common/dist/types";
import { ResponseMessage } from "../core/communication/ResponseMessage";
import { CredentialRequestHelper } from "./CredentialRequestHelper";

export type CredentialIssuerCreateOptions = {
	authorizationServerUrl: string,
	stateStore?: GenericStore<string, State>,

	secret: string, // used for HS512 JWT signatures when issuing nonce values

	credentialRequestHelper: CredentialRequestHelper,
	clockTolerance: number,
	nonceExpirationTime?: string, // ex. '10s' for 10 seconds. Follows the same format as the JOSE library
	getAllTrustedPemCertificates: () => Promise<string[]>,
	findAccount: FindAccount,
	credentialSigner: CredentialSigner,
	proofTypesSupported: ProofTypeSupported[],
	credentialRequestEncryption?: {
		encryptionRequired: boolean,
		keypair: {
			alg: string,
			publicKeyJwk: JWK,
			privateKeyJwk: JWK,
		}
	},
	credentialResponseEncryption?: {
		encryptionRequired: boolean,
	},
	requireKeyBindingInCredentialConfigurationIds: string[],
	x5c: string[],
	introspectionEndpointBasicAuthString: string,
	display?: OpenidCredentialIssuerMetadata["display"],
	vctDocumentProvider?: VctDocumentProvider,
	deferredCredentialResponseInterval?: number,
}

export interface IssuerOpenID4VCI {

	generateCredentialOffer(credentialOfferCreateOptions: {
		credentialConfigurationId: string,
	}): Promise<CredentialOfferCreateSuccess>;


	generateCredentialOfferWithSingleUseCredentialOfferUri(credentialOfferId: string): Promise<URL | null>;
	getCredentialOffer(credentialOfferId: string, revoke: boolean): Promise<CredentialOffer | null>;


	registerSupportedCredentialConfiguration(credentialConfigurationId: string, credConf: CredentialConfigurationSupported, discloseFrame?: Record<string, unknown>): void;

	getMetadata(): Promise<OpenidCredentialIssuerMetadata>;
	issueNonce(): Promise<ResponseMessage>;

	issueCredential(issueCredentialOptions: IssueCredentialRequestOptions): Promise<IssueCredentialResponse>;
}



/**
 *
 * @param url the Credential Issuer Identifier according to OpenID4VCI 1.0 spec
 * @param credentialIssuerCreateOptions
 * @returns
 */
export function createIssuerOpenID4VCI(url: string, credentialIssuerCreateOptions: CredentialIssuerCreateOptions): IssuerOpenID4VCI {

	const encoder = new TextEncoder();

	const deferredCredentialResponseInterval = credentialIssuerCreateOptions.deferredCredentialResponseInterval ?? 60;

	const store = credentialIssuerCreateOptions.stateStore ?? new MemoryStore(10000);
	const secretManager = createMemorySecretManager(
		credentialIssuerCreateOptions.secret,
		credentialIssuerCreateOptions.clockTolerance,
		credentialIssuerCreateOptions.nonceExpirationTime
	);

	if (credentialIssuerCreateOptions.credentialRequestEncryption?.keypair?.publicKeyJwk &&
		!('kid' in credentialIssuerCreateOptions.credentialRequestEncryption?.keypair?.publicKeyJwk)) {
		throw new Error("Could not create issuer because 'kid' is missing from credentialIssuerCreateOptions.credentialRequestEncryption?.publicKeyJwk");
	}

	const metadata = buildMetadata(url, credentialIssuerCreateOptions);

	const disclosureFrameMap = new Map<string, Record<string, unknown>>();

	return {
		generateCredentialOffer: async (credentialOfferCreateOptions: {
			credentialConfigurationId: string,
		}): Promise<CredentialOfferCreateSuccess> => {
			const credentialOffer: CredentialOffer = {
				credential_issuer: url,
				credential_configuration_ids: [credentialOfferCreateOptions.credentialConfigurationId],
				grants: { authorization_code: {} }
			};
			const container = new URL("openid-credential-offer://");
			container.searchParams.append('credential_offer', JSON.stringify(credentialOffer));
			const id = generateRandomIdentifier(18);
			await store.set(id, {
				id: id,
				credentialOfferUrlContainer: container.toString(),
				attestedKeys: null,
				sub: null,
				transactionId: null,
				clientId: null,
				scope: null,
				credentialConfigurationId: null,
			});

			return {
				credentialOfferId: id,
				credentialOfferUrlContainer: container,
			};
		},

		generateCredentialOfferWithSingleUseCredentialOfferUri: async (credentialOfferId: string): Promise<URL | null> => {
			const state = await store.get(credentialOfferId);
			if (!state) {
				return null;
			}
			const singleUseUrl = new URL(url + '/credential-offer/' + credentialOfferId);
			const container = new URL("openid-credential-offer://");
			container.searchParams.set('credential_offer_uri', singleUseUrl.toString());
			return container;
		},

		getCredentialOffer: async (credentialOfferId: string, revoke: boolean = false): Promise<CredentialOffer | null> => {
			const state = await store.get(credentialOfferId);
			if (!state || !state.credentialOfferUrlContainer) {
				return null;
			}
			if (revoke) {
				await store.delete(credentialOfferId);
			}
			const container = new URL(state.credentialOfferUrlContainer);
			const credentialOffer = CredentialOfferSchema.safeParse(JSON.parse(container.searchParams.get('credential_offer') as string));
			return credentialOffer.success ? credentialOffer.data : null;

		},

		issueNonce: async () => {
			return {
				headers: {
					'Content-Type': 'application/json',
				},
				data: { c_nonce: await secretManager.secretSigner({ }) },
				status: 200,
			}
		},

		registerSupportedCredentialConfiguration: (credentialConfigurationId, credConf, disclosureFrame) => {
			metadata.credential_configurations_supported[credentialConfigurationId] = {
				...credConf,
				proof_types_supported: {
					...credConf.proof_types_supported,
					"jwt": {
						proof_signing_alg_values_supported: ["ES256"]
					},
					"attestation": credConf.proof_types_supported?.attestation?.key_attestations_required ? {
						proof_signing_alg_values_supported: ["ES256"],
						key_attestations_required: { },
					} : undefined,
				},
			};
			if (disclosureFrame) {
				disclosureFrameMap.set(credentialConfigurationId, disclosureFrame);
			}
		},

		getMetadata: async (signMetadata: boolean = true) => {
			const m = OpenidCredentialIssuerMetadataSchema.parse(metadata);
			// use credentialIssuerCreateOptions.vctDocumentProvider to override the claims from VCT Document
			await Promise.all(Object.values(m.credential_configurations_supported).map(async (conf) => {
				if (conf.format === VerifiableCredentialFormat.DC_SDJWT || conf.format === VerifiableCredentialFormat.VC_SDJWT) {
					const vct = conf.vct;
					if (credentialIssuerCreateOptions.vctDocumentProvider) {
						const doc = await credentialIssuerCreateOptions.vctDocumentProvider.getVctMetadataDocument(vct);
						if (doc) {
							const claims = convertSdjwtvcToOpenid4vciClaims(doc.claims);
							conf.claims = claims;
							return;
						}
						return;
					}
					return;
				}
				return;
			}));

			if (signMetadata) {
				const signer = credentialIssuerCreateOptions.credentialSigner.signer();
				const publicKeyJwk = await credentialIssuerCreateOptions.credentialSigner.getPublicKeyJwk();
				const [header, payload] = [
					encoder.encode(JSON.stringify({ alg: publicKeyJwk.alg as string, x5c: credentialIssuerCreateOptions.x5c, typ: "openidvci-issuer-metadata+jwt" })),
					encoder.encode(JSON.stringify({ ...m, iat: Math.floor(new Date().getTime() / 1000), sub: url, })),
				];
				const data = `${toBase64Url(header)}.${toBase64Url(payload)}`;
				const signature = await signer(data);
				m.signed_metadata = `${data}.${signature}`;
			}
			return OpenidCredentialIssuerMetadataSchema.parse(m);
		},

		issueCredential: async (issueCredentialOpts): Promise<IssueCredentialResponse> => {
			// decrypt credential request if received as encrypted
			const issueCredentialOptionsResult = await handleEncryptedCredentialRequest(
				metadata,
				issueCredentialOpts,
				credentialIssuerCreateOptions.credentialRequestEncryption
			);
			if (!issueCredentialOptionsResult.ok) {
				return sendError(issueCredentialOptionsResult.error, issueCredentialOptionsResult.error_description);
			}
			const issueCredentialOptions = issueCredentialOptionsResult.value;
			
			const response = await handleCredentialIdentifierCredentialRequest(issueCredentialOptions);
			if (response !== undefined) {
				return response as IssueCredentialResponse;
			}



			const { credential_configuration_id } = await (async () => {
				if ('credential_configuration_id' in issueCredentialOptions.request.data) {
					return { credential_configuration_id: issueCredentialOptions.request.data.credential_configuration_id };
				}
				else if ('transaction_id' in issueCredentialOptions.request.data) {
					const transaction_id = issueCredentialOptions.request.data.transaction_id;
					const allStates = await store.getAll();
					const s = allStates.filter((s) => s.transactionId === transaction_id)[0];
					if (!s.credentialConfigurationId) {
						return { credential_configuration_id: s.credentialConfigurationId };
					}
				}
				return { credential_configuration_id: null };
			})();

			if (credential_configuration_id === null) {
				return sendError(CredentialRequestErrors.InvalidRequest, "No credential configuration is defined in the request");
			}

			// access token validation
			const accessTokenValidationResult = await validateAccessToken(
				credential_configuration_id,
				metadata,
				issueCredentialOptions,
				credentialIssuerCreateOptions
			);

			if (!accessTokenValidationResult.ok) {
				return sendError(accessTokenValidationResult.error, accessTokenValidationResult.error_description);
			}

			const { sub, client_id, scope } = accessTokenValidationResult.value;
			const stateId = generateRandomIdentifier(12);
			const state = {
				id: stateId,
				sub: sub,
				clientId: client_id,
				credentialOfferUrlContainer: null,
				attestedKeys: null,
				scope: scope,
				transactionId: null,
			} as State;
			await store.set(stateId, state);

			// account resolution
			const account = await credentialIssuerCreateOptions.findAccount({
				method: 'POST',
				url: "/credential",
				credentialRequestHelper: credentialIssuerCreateOptions.credentialRequestHelper,
				request: { client: { cliendId: client_id, }, },
			}, sub, "");


			if (account === undefined) {
				return sendError(CredentialRequestErrors.CredentialRequestDenied, "Not allowed");
			}

			if (!('proofs' in issueCredentialOptions.request.data) === undefined &&
				credentialIssuerCreateOptions.requireKeyBindingInCredentialConfigurationIds.includes(credential_configuration_id)) { // check if key-binding is required and no proofs provided

				return sendError(CredentialRequestErrors.CredentialRequestDenied, `Credetial configuration id '${credential_configuration_id}' can only be issued with key-binding.`);
			}

			// 'proofs' validation
			if ('proofs' in issueCredentialOptions.request.data && issueCredentialOptions.request.data.proofs !== undefined) {
				const proofsVerificationResult = await verifyProofsWrapper(issueCredentialOptions.request.data.proofs, {
					clockTolerance: credentialIssuerCreateOptions.clockTolerance,
					getAllTrustedPemCertificates: credentialIssuerCreateOptions.getAllTrustedPemCertificates,
					requiredVerificationMechanisms: ["x5c"],
					credentialIssuerIdentifier: url,
				});

				if (!proofsVerificationResult.ok) {
					return sendError(proofsVerificationResult.error, proofsVerificationResult.error_description);
				}
				const { attested_keys } = proofsVerificationResult.value;
				const claimsFuture = account?.claims ? await account?.claims("issue", scope) : null;
				if (claimsFuture === null) {
					return sendError(CredentialRequestErrors.CredentialRequestDenied, "Could not retrieve claims for this account");
				}

				// update credential_configuration_id from request and (attestedKeys, transactionid) from claimsFuture
				state.attestedKeys = attested_keys;
				state.transactionId = claimsFuture.transaction_id;
				state.credentialConfigurationId = credential_configuration_id;
				await store.set(stateId, state);

				if (claimsFuture.status === 'pending') { // if not resolved then respond with transaction_id
					const responseOpts: PlainIssueCredentialResponse = { status: 200, headers: { "content-type": "application/json" }, data: { transaction_id: claimsFuture.transaction_id, interval: deferredCredentialResponseInterval } };
					const send = await sendCredentialResponse(metadata, issueCredentialOptions, responseOpts, credentialIssuerCreateOptions);
					if (!send.ok) {
						return sendError(send.error, send.error_description);
					}
					return send.value;
				}
				if (claimsFuture.status === 'rejected') {
					return sendError(CredentialRequestErrors.CredentialRequestDenied, "Claims could not be retrieved becuase the request is rejected by the Credential Issuer");
				}

				const credentialsBindingResult = await signCredentials(
					metadata,
					claimsFuture.data.claims,
					attested_keys,
					disclosureFrameMap,
					issueCredentialOptions,
					credentialIssuerCreateOptions
				);
				if (!credentialsBindingResult.ok) {
					return sendError(credentialsBindingResult.error, credentialsBindingResult.error_description);
				}
				const credentials = credentialsBindingResult.value;
				const responseOpts: PlainIssueCredentialResponse = { status: 200, headers: { "content-type": "application/json" }, data: { credentials: credentials.map((credential: string) => ({ credential })) } };
				const send = await sendCredentialResponse(metadata, issueCredentialOptions, responseOpts, credentialIssuerCreateOptions);
				if (!send.ok) {
					return sendError(send.error, send.error_description);
				}
				return send.value;
			}


			// check if proofs where not provided for a credential configuration id that exists in the requireKeyBindingInCredentialConfigurationIds array
			if (!('proofs' in issueCredentialOptions.request.data) &&
				credentialIssuerCreateOptions.requireKeyBindingInCredentialConfigurationIds.includes(credential_configuration_id)) {
				return sendError(CredentialRequestErrors.InvalidRequest, "The specific credential configuration requires key-binding")
			}
			return sendError(CredentialRequestErrors.InvalidRequest, "No credential configuration is defined in the request");
		},
	}
}

import { CredentialConfigurationSupported, CredentialOffer, OpenidCredentialIssuerMetadata } from "wallet-common";
import { JWK } from "jose";
import { ResponseMessage } from "../core/communication/ResponseMessage";
import { CredentialRequestError } from "./CredentialRequest/CredentialRequestError";

export type CredentialOfferCreateSuccess = { credentialOfferId: string, credentialOfferUrlContainer: URL };

export type IssueCredentialRequestBase = {
	proofs?: ({ jwt: string } | { attestation: string })[],
	credential_response_encryption?: {
		jwk: JWK,
		enc: string,
		zip?: string,
	},
}

export type PlainIssueCredentialRequestOptions = {
	request: {
		headers: { 'Content-Type': 'application/json', 'Authorization': string, 'DPoP': string },
		data: ({ credential_identifier: string; credential_configuration_id?: never } & IssueCredentialRequestBase) |
		({ credential_configuration_id: string; credential_identifier?: never } & IssueCredentialRequestBase);
	}
}


export type EncryptedIssueCredentialRequestOptions = {
	request: {
		headers: { 'Content-Type': 'application/jwt', 'Authorization': string, 'DPoP': string },
		data: string,
	};
};

export type IssueCredentialRequestOptions = EncryptedIssueCredentialRequestOptions | PlainIssueCredentialRequestOptions;

export type PlainIssueCredentialResponse = ResponseMessage & { headers: { 'Content-Type': 'application/json' } } & ({
		data: { credentials: string[] },
		status: 200,
	} | {
		data: {
			error: CredentialRequestError,
			error_description: string,
		},
		status: 400,
	})

export type EncryptedIssueCredentialResponse = ResponseMessage & {
	headers: { 'Content-Type': 'application/jwt' },
	data: string,
}

export type IssueCredentialResponse = EncryptedIssueCredentialResponse | PlainIssueCredentialResponse;

export interface IssuerOpenID4VCI {

	generateCredentialOffer(credentialOfferCreateOptions: {
		credentialConfigurationId: string,
	}): Promise<CredentialOfferCreateSuccess>;


	generateCredentialOfferWithSingleUseCredentialOfferUri(credentialOfferId: string): Promise<URL | null>;
	getCredentialOffer(credentialOfferId: string, revoke: boolean): Promise<CredentialOffer | null>;


	registerSupportedCredentialConfiguration(credentialConfigurationId: string, credConf: CredentialConfigurationSupported): void;

	getMetadata(): Promise<OpenidCredentialIssuerMetadata>;
	issueNonce(): Promise<ResponseMessage>;

	issueCredential(issueCredentialOptions: IssueCredentialRequestOptions): Promise<IssueCredentialResponse>;
}

import { JWK } from "jose";
import { ResponseMessage } from "../core/communication/ResponseMessage";
import { CredentialRequestError } from "./CredentialRequest/CredentialRequestError";

export type CredentialOfferCreateSuccess = { credentialOfferId: string, credentialOfferUrlContainer: URL };

export type IssueCredentialRequestBase = {
	credential_response_encryption?: {
		jwk: JWK,
		enc: string,
		zip?: string,
	},
}

export type IssueCredentialRequestProofsExtension = {
	proofs?: ({ jwt: string } | { attestation: string })[],
}

export type PlainIssueCredentialRequestOptions = {
	request: {
		headers: { 'Content-Type': 'application/json', 'Authorization': string, 'DPoP': string },
		data: ({ credential_identifier: string; } & IssueCredentialRequestProofsExtension & IssueCredentialRequestBase) |
		({ credential_configuration_id: string; } & IssueCredentialRequestProofsExtension & IssueCredentialRequestBase) |
		({ transaction_id: string; } & IssueCredentialRequestBase);
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
	data: { transaction_id: string, interval: number },
	status: 200,
} |{
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


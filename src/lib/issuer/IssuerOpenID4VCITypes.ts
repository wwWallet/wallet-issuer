import { JWK } from 'jose';
import { ResponseMessage } from 'wallet-common';
import { CredentialRequestError } from './CredentialRequest/CredentialRequestError';

export type CredentialOfferCreateSuccess = { credentialOfferId: string; credentialOfferWithReference: URL, txCode?: string };

export type IssueCredentialRequestBase = {
	credential_response_encryption?: {
		jwk: JWK;
		enc: string;
		zip?: string;
	};
};

export type IssueCredentialRequestProofsExtension = {
	proofs?: { jwt: string[] } | { attestation: string[] };
};

export type PlainIssueCredentialRequestOptions = {
	request: {
		headers: { 'content-type': 'application/json'; authorization: string; dpop: string };
		data: ({ credential_identifier: string } & IssueCredentialRequestProofsExtension & IssueCredentialRequestBase) | ({ credential_configuration_id: string } & IssueCredentialRequestProofsExtension & IssueCredentialRequestBase) | ({ transaction_id: string } & IssueCredentialRequestBase);
	};
};

export type EncryptedIssueCredentialRequestOptions = {
	request: {
		headers: { 'content-type': 'application/jwt'; authorization: string; dpop: string };
		data: string;
	};
};

export type IssueCredentialRequestOptions = EncryptedIssueCredentialRequestOptions | PlainIssueCredentialRequestOptions;

export type PlainIssueCredentialResponse = ResponseMessage & { headers: { 'content-type': 'application/json' } } & (
		| {
			data: { credentials: { credential: string }[] };
			status: 200;
		}
	| {
			data: { transaction_id: string; interval: number };
			status: 202;
	}
	| {
			data: {
				error: CredentialRequestError;
				error_description: string;
			};
			status: 400;
		}
	);

export type EncryptedIssueCredentialResponse = ResponseMessage & {
	headers: { 'content-type': 'application/jwt' };
	data: string;
};

export type IssueCredentialResponse = EncryptedIssueCredentialResponse | PlainIssueCredentialResponse;

import { CredentialRequestHelper } from '../CredentialRequestHelper';
import { Account } from './Account';

export type FindAccount = (
	ctx: {
		url: string;
		method: string;
		credentialRequestHelper: CredentialRequestHelper;
		request: { client: { cliendId: string } | null; transactionId: string | null };
	},
	sub: string,
	token: string,
) => Promise<Account | undefined>;

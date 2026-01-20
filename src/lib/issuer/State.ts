import { JWK } from 'jose';

export type State = {
	id: string;

	credentialOfferUrlContainer: string | null;

	sub: string | null;
	clientId: string | null;
	attestedKeys: JWK[] | null;
	credentialConfigurationId: string | null;
	transactionId: string | null;
	scope: string | null;

	iso_datetime_created: string;
};

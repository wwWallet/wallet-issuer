export type IntrospectionResponse = {
	active: boolean;
	scope?: string;
	client_id?: string;
	username?: string;
	token_type?: string;
	exp?: number;
	iat?: number;
	nbf?: number;
	sub?: string;
	aud?: string;
	iss?: string;
	jti?: string;
	issuer_state?: string;
	cnf?: { jkt?: string };
}

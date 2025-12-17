import { jwtVerify, SignJWT } from "jose";
import { importHS512Key } from "../core/HS512";
import { generateRandomIdentifier } from "../core/generateRandomIdentifier";



export interface SecretManager {
	secretSigner(payload: unknown): Promise<string>;
	secretVerifier(jwt: string): Promise<boolean>;
}

export const createMemorySecretManager = (secret: string, clockTolerance: number = 60, expirationTime: string = '10s'): SecretManager => {

	return {
		secretSigner: async (payload: unknown) => {
			const key = await importHS512Key(secret);
			return new SignJWT(payload as any)
				.setProtectedHeader({ alg: "HS512" })
				.setIssuedAt()
				.setNotBefore(new Date())
				.setExpirationTime(expirationTime)
				.setJti(generateRandomIdentifier(16))
				.sign(key);
		},
		secretVerifier: async (jwt: string) => {
			const key = await importHS512Key(secret);
			return jwtVerify(jwt, key, {
				requiredClaims: ["iat", "jti", "exp", "nbf"],
				clockTolerance: clockTolerance,
			}).then(() => true).catch(() => false);
		},
	}
}

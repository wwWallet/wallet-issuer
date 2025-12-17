export const ProofTypesSupported = {
	JWT: "jwt",
	ATTESTATION: "attestation",
} as const;

export type ProofTypeSupported = typeof ProofTypesSupported[keyof typeof ProofTypesSupported];
